# vu9p_bridge.tcl - vivado_lab JTAG-AXI register bridge for suprminer-fpga (--fpga vu9p), one board per bridge.
# usage: vivado_lab -mode batch -nojournal -nolog -source vu9p_bridge.tcl -tclargs <jtag serial> <tcp port> [hw_server host:port]
# Algorithm-agnostic: it only moves 32-bit words over the bitstream's JTAG-AXI master; the miner's driver gives them meaning.
# Line protocol on 127.0.0.1:<port> (one client at a time), hex without 0x:
#   R <addr>                 -> OK <data>
#   W <addr> <data>          -> OK
#   RB <addr> <n>            -> OK <d0> <d1> ... (n sequential 32-bit words)
#   WB <addr> <d0> <d1> ...  -> OK          (sequential 32-bit words)
#   TEMP                     -> OK C=<temp> VCCINT=<v> VCCAUX=<v> VCCBRAM=<v>
#   PING                     -> OK <number of hw_axi cores> (liveness)
#   QUIT                     -> OK (closes)
# On client EOF the bridge writes run=0 (0x200 <- 0) so a dead host never leaves a card searching.
lassign $argv serial port hwserver
if {$serial eq "" || $port eq ""} { puts "BRIDGE_ERR usage: serial port \[hw_server\]"; exit 1 }
if {$hwserver eq ""} { set hwserver 127.0.0.1:3121 }
open_hw_manager
connect_hw_server -url $hwserver
set targets [get_hw_targets *$serial]
if {[llength $targets] != 1} { puts "BRIDGE_ERR expected one target $serial, got [llength $targets]"; exit 1 }
current_hw_target [lindex $targets 0]
open_hw_target
set devs [get_hw_devices xcvu9p*]
if {[llength $devs] != 1} { puts "BRIDGE_ERR expected one xcvu9p on $serial"; exit 1 }
set dev [lindex $devs 0]
current_hw_device $dev
refresh_hw_device $dev -quiet
set axis [get_hw_axis]
if {[llength $axis] != 1} { puts "BRIDGE_ERR expected one hw_axi (is the mining bitstream loaded? --program), got [llength $axis]"; exit 1 }
set axi [lindex $axis 0]
set sysmons [get_hw_sysmons -of_objects $dev]

proc axi_wr {addr data} {
    global axi
    set txn [create_hw_axi_txn -force wr_txn $axi -type write -address [format %08x $addr] -data [format %08x $data]]
    run_hw_axi -quiet $txn
}
proc axi_rd {addr} {
    global axi
    set txn [create_hw_axi_txn -force rd_txn $axi -type read -address [format %08x $addr]]
    run_hw_axi -quiet $txn
    return [expr 0x[get_property DATA $txn]]
}
proc temp_line {} {
    global sysmons
    set m [lindex $sysmons 0]
    refresh_hw_sysmon $m
    return "OK C=[get_property TEMPERATURE $m] VCCINT=[get_property VCCINT $m] VCCAUX=[get_property VCCAUX $m] VCCBRAM=[get_property VCCBRAM $m]"
}
set ::owner ""
proc safe_stop {} { catch {axi_wr 0x200 0} }
proc handle {chan line} {
    set parts [split [string trim $line]]
    set cmd [lindex $parts 0]
    if {[catch {
        switch -- $cmd {
            R    { set v [axi_rd [expr 0x[lindex $parts 1]]]; set resp [format "OK %08x" $v] }
            W    { axi_wr [expr 0x[lindex $parts 1]] [expr 0x[lindex $parts 2]]; set resp "OK" }
            RB   { set a [expr 0x[lindex $parts 1]]; set n [expr [lindex $parts 2]]; set resp "OK"
                   for {set i 0} {$i < $n} {incr i} { append resp [format " %08x" [axi_rd [expr {$a + 4*$i}]]] } }
            WB   { set a [expr 0x[lindex $parts 1]]; set i 0
                   foreach d [lrange $parts 2 end] { axi_wr [expr {$a + 4*$i}] [expr 0x$d]; incr i }
                   set resp "OK" }
            TEMP { set resp [temp_line] }
            PING { set resp "OK [llength [get_hw_axis]]" }
            QUIT { safe_stop; puts $chan "OK"; flush $chan; close $chan; set ::owner ""; return }
            default { set resp "ERR grammar" }
        }
    } err]} { set resp "ERR $err" }
    puts $chan $resp
    flush $chan
}
proc on_read {chan} {
    if {[catch {set n [gets $chan line]}] || ($n < 0 && [eof $chan])} {
        safe_stop; catch {close $chan}; set ::owner ""; puts "BRIDGE_CLIENT_GONE run=0"; flush stdout; return
    }
    if {$n >= 0} { handle $chan $line }
}
proc on_accept {chan addr p} {
    if {$::owner ne ""} { catch {puts $chan "ERR BUSY"; flush $chan; close $chan}; return }
    set ::owner $chan
    fconfigure $chan -blocking 0 -buffering line -translation lf
    fileevent $chan readable [list on_read $chan]
    puts "BRIDGE_CLIENT $addr:$p"; flush stdout
}
socket -server on_accept -myaddr 127.0.0.1 $port
puts "BRIDGE_READY serial=$serial port=$port"
flush stdout
vwait ::forever
