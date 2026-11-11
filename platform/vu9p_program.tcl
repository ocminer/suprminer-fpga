# vu9p_program.tcl - program one VU9P board (BCU-1525 etc.) by JTAG serial with a bitstream (suprminer-fpga --program).
# usage: vivado_lab -mode batch -nojournal -nolog -source vu9p_program.tcl -tclargs <serial> <bitfile> [hw_server host:port]
lassign $argv serial bit hwserver
if {$hwserver eq ""} { set hwserver 127.0.0.1:3121 }
open_hw_manager
connect_hw_server -url $hwserver
set targets [get_hw_targets *$serial]
if {[llength $targets] != 1} { puts "PROGRAM_ERR expected one target $serial"; exit 1 }
current_hw_target [lindex $targets 0]
open_hw_target
set dev [lindex [get_hw_devices xcvu9p*] 0]
current_hw_device $dev
set_property PROGRAM.FILE $bit $dev
program_hw_devices $dev
refresh_hw_device $dev
set m [lindex [get_hw_sysmons -of_objects $dev] 0]
refresh_hw_sysmon $m
puts "PROGRAM_DONE serial=$serial file=$bit temp=[get_property TEMPERATURE $m] hw_axis=[llength [get_hw_axis]]"
close_hw_target
