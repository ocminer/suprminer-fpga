# BS1 one-core JTAG-AXI TCP bridge. This script does not program the FPGA.
# Usage: Vivado Lab -mode batch -source vu9p_bs1_bridge.tcl -tclargs SERIAL PORT
# The listener is local-only; one client owns work until it disconnects.

namespace eval vu9p_bs1_protocol {
    variable owner_channel ""
    variable exact_build_id 0x5a3d0001

    proc parse_build_id {text} {
        if {![regexp {^[0-9A-Fa-f]{8}$} $text]} {
            error "BUILD_ID must be exactly eight hex digits"
        }
        scan $text %x value
        return $value
    }

    proc require_exact_invocation {serial port build_id} {
        variable exact_build_id
        if {![regexp {^[A-Za-z0-9_-]{1,128}$} $serial]} {
            error "serial must be a literal hardware-target serial"
        }
        if {![regexp {^[1-9][0-9]{0,4}$} $port] || $port > 65535} {
            error "port must be between 1 and 65535"
        }
        if {$build_id != $exact_build_id} { error "build ID is not exact BS1" }
        return 1
    }

    proc require_target_name {name serial} {
        if {[file tail $name] ne $serial} {
            error "hardware target does not have the exact requested serial"
        }
        return 1
    }

    proc parse_request {line} {
        if {[regexp {^WORK ([0-9A-Fa-f]{152}) ([0-9A-Fa-f]{8}) ([0-9A-Fa-f]{8})$} \
                $line -> header target base]} {
            return [dict create command WORK header $header target $target base $base]
        }
        foreach command {POLL STOP PING TEMP QUIT} {
            if {$line eq $command} {
                return [dict create command $command]
            }
        }
        error "invalid request grammar"
    }

    proc format_pong {build_id} {
        if {![string is entier -strict $build_id] || $build_id < 0 ||
            $build_id > 0xffffffff} {
            error "build_id is outside uint32"
        }
        return [format "PONG %08x" $build_id]
    }

    proc format_poll {found nonce hash7 hashes_done last_hash7} {
        if {![string is entier -strict $hashes_done] || $hashes_done < 0 ||
            $hashes_done > 18446744073709551615} {
            error "hashes_done is outside uint64"
        }
        foreach value [list $nonce $hash7 $last_hash7] {
            if {![string is entier -strict $value] || $value < 0 ||
                $value > 0xffffffff} {
                error "poll hex field is outside uint32"
            }
        }
        if {$found} {
            return [format "FOUND %08x %08x %s %08x" \
                $nonce $hash7 $hashes_done $last_hash7]
        }
        return [format "NONE %s %08x" $hashes_done $last_hash7]
    }

    # The legacy BS1 register file has no atomic counter snapshot.  A
    # high/low/high loop rejects low-word rollover between JTAG word reads; it
    # does not retrofit a CDC mailbox into the frozen image.  Runtime
    # regression/overrun/rate guards therefore remain mandatory.  The caller
    # supplies a read command so hostile tests can force rollover and failure.
    proc coherent_counter {read_command} {
        for {set attempt 0} {$attempt < 8} {incr attempt} {
            set high_before [uplevel #0 [list $read_command 0x6C]]
            set low [uplevel #0 [list $read_command 0x68]]
            set high_after [uplevel #0 [list $read_command 0x6C]]
            if {$high_before == $high_after} {
                return [expr {(wide($high_after) << 32) | wide($low)}]
            }
        }
        error "hash counter did not yield a coherent high/low/high sample"
    }

    proc claim_owner {channel} {
        variable owner_channel
        if {$owner_channel ne ""} {
            return 0
        }
        set owner_channel $channel
        return 1
    }

    proc is_owner {channel} {
        variable owner_channel
        return [expr {$owner_channel eq $channel}]
    }

    proc release_owner {channel} {
        variable owner_channel
        if {$owner_channel ne $channel} {
            return 0
        }
        set owner_channel ""
        return 1
    }

    proc terminal_action {reason} {
        if {[lsearch -exact {GRAMMAR WORK_IO POLL_IO STOP_IO TEMP_IO QUIT \
                READ_ERROR CALLBACK_ERROR EOF} $reason] < 0} {
            error "unknown owner terminal reason"
        }
        return STOP_CLOSE
    }

    proc stop_outcome {stopped} {
        if {$stopped ni {0 1}} {
            error "stop outcome must be boolean"
        }
        return [expr {$stopped ? "RELEASE" : "QUARANTINE_EXIT"}]
    }

    proc latch_stop_outcome {stopped} {
        set outcome [stop_outcome $stopped]
        if {$outcome eq "QUARANTINE_EXIT"} {
            set ::bridge_fatal_stop_failure 1
            set ::forever 1
        }
        return $outcome
    }

    proc require_single_sysmon {monitors context} {
        set count [llength $monitors]
        if {$count != 1} {
            error "expected exactly one master-SLR hw_sysmon on $context, got $count"
        }
        return [lindex $monitors 0]
    }
}

if {[info exists ::env(VU9P_BS1_PROTOCOL_TEST_ONLY)] &&
    $::env(VU9P_BS1_PROTOCOL_TEST_ONLY) eq "1"} {
    return
}

if {$argc != 2} {
    puts "BRIDGE_ERR usage: vu9p_bs1_bridge.tcl <serial> <port>"
    exit 2
}
set serial [lindex $argv 0]
set port [lindex $argv 1]
set expected_build_id 0x5a3d0001
if {[catch {
    vu9p_bs1_protocol::require_exact_invocation $serial $port $expected_build_id
} invocation_error]} {
    puts "BRIDGE_ERR $invocation_error"
    exit 2
}

open_hw_manager
connect_hw_server -allow_non_jtag
set targets [get_hw_targets *$serial]
if {[llength $targets] != 1} {
    puts "BRIDGE_ERR expected one target $serial, got [llength $targets]"
    exit 1
}
set target [lindex $targets 0]
vu9p_bs1_protocol::require_target_name [get_property NAME $target] $serial
current_hw_target $target
open_hw_target
set devs [get_hw_devices xcvu9p*]
if {[llength $devs] != 1} {
    puts "BRIDGE_ERR expected one xcvu9p on $serial, got [llength $devs]"
    exit 1
}
set dev [lindex $devs 0]
current_hw_device $dev
refresh_hw_device $dev -quiet
puts "BS1_BRIDGE_IDENTITY device_count=1"
set startup_monitors [get_hw_sysmons -of_objects $dev]
if {[catch {vu9p_bs1_protocol::require_single_sysmon \
        $startup_monitors $serial} sysmon_error]} {
    puts "BRIDGE_ERR $sysmon_error"
    exit 1
}
set bridge_sysmon_count 1
set axes [get_hw_axis]
if {[llength $axes] != 1} {
    puts "BRIDGE_ERR expected one hw_axi, got [llength $axes]"
    exit 1
}
set axi [lindex $axes 0]

proc axi_wr {address data} {
    global axi
    set transaction [create_hw_axi_txn -force wr_txn $axi -type write \
        -address [format %08x $address] -data $data]
    run_hw_axi -quiet $transaction
}

proc axi_rd {address} {
    global axi
    set transaction [create_hw_axi_txn -force rd_txn $axi -type read \
        -address [format %08x $address]]
    run_hw_axi -quiet $transaction
    return [expr 0x[get_property DATA $transaction]]
}

proc master_slr_temp {} {
    global dev serial
    set monitors [get_hw_sysmons -of_objects $dev]
    set monitor [vu9p_bs1_protocol::require_single_sysmon $monitors $serial]
    if {[llength [info commands refresh_hw_sysmon]] != 1} {
        error "refresh_hw_sysmon unavailable"
    }
    refresh_hw_sysmon $monitor
    return "TEMP MASTER_SLR_ONLY C=[get_property TEMPERATURE $monitor] VCCINT=[get_property VCCINT $monitor] VCCAUX=[get_property VCCAUX $monitor] VCCBRAM=[get_property VCCBRAM $monitor]"
}

proc stop_and_prove_idle {} {
    axi_wr 0x58 00000000
    set status [axi_rd 0x5C]
    if {(($status >> 1) & 1) != 0} {
        error "RUN remained asserted after STOP"
    }
    return $status
}

proc direct_stats {} {
    set hashes_done [vu9p_bs1_protocol::coherent_counter axi_rd]
    set last_hash7 [axi_rd 0x70]
    return [list $hashes_done $last_hash7]
}

proc do_work {header target base} {
    stop_and_prove_idle
    axi_wr 0x58 00000002
    axi_wr 0x58 00000000
    for {set word 0} {$word < 19} {incr word} {
        set b0 [string range $header [expr {8*$word+0}] [expr {8*$word+1}]]
        set b1 [string range $header [expr {8*$word+2}] [expr {8*$word+3}]]
        set b2 [string range $header [expr {8*$word+4}] [expr {8*$word+5}]]
        set b3 [string range $header [expr {8*$word+6}] [expr {8*$word+7}]]
        axi_wr [expr {4*$word}] "$b3$b2$b1$b0"
    }
    axi_wr 0x50 $target
    axi_wr 0x54 $base
    axi_wr 0x78 00000001
    axi_wr 0x58 00000001
}

proc stop_and_close_owner {channel response reason} {
    vu9p_bs1_protocol::terminal_action $reason
    if {![vu9p_bs1_protocol::is_owner $channel]} {
        catch {close $channel}
        return 0
    }
    set stopped [expr {![catch {stop_and_prove_idle}]}]
    set outcome [vu9p_bs1_protocol::latch_stop_outcome $stopped]
    if {$response ne ""} {
        if {$response eq "OK" && !$stopped} {
            set response "ERR IO"
        }
        catch {puts $channel $response}
        catch {flush $channel}
    }
    vu9p_bs1_protocol::release_owner $channel
    catch {fileevent $channel readable {}}
    catch {close $channel}
    catch {puts "BRIDGE_OWNER_CLOSED reason=$reason stop_ok=$stopped outcome=$outcome"}
    catch {flush stdout}
    return $stopped
}

if {[catch {stop_and_prove_idle} startup_stop_error]} {
    puts "BRIDGE_ERR startup STOP/idle proof failed: $startup_stop_error"
    exit 1
}
set build_id [axi_rd 0x74]
if {$build_id != $expected_build_id || $build_id != 0x5a3d0001} {
    puts "BRIDGE_ERR build_id actual=[format %08x $build_id] expected=5a3d0001"
    exit 1
}

proc handle_line {channel line} {
    global build_id
    if {![vu9p_bs1_protocol::is_owner $channel]} {
        catch {close $channel}
        return
    }
    if {[catch {set request [vu9p_bs1_protocol::parse_request $line]}]} {
        stop_and_close_owner $channel "ERR GRAMMAR" GRAMMAR
        return
    }
    set command [dict get $request command]
    switch -- $command {
        WORK {
            if {[catch {do_work [dict get $request header] \
                    [dict get $request target] [dict get $request base]}]} {
                stop_and_close_owner $channel "ERR IO" WORK_IO
                return
            }
            puts $channel "OK"
        }
        POLL {
            if {[catch {
                set status [axi_rd 0x5C]
                if {($status & 1) != 0} {
                    set nonce [axi_rd 0x60]
                    set hash7 [axi_rd 0x64]
                    lassign [direct_stats] hashes_done last_hash7
                    axi_wr 0x78 00000001
                    set response [vu9p_bs1_protocol::format_poll 1 $nonce \
                        $hash7 $hashes_done $last_hash7]
                } else {
                    lassign [direct_stats] hashes_done last_hash7
                    set response [vu9p_bs1_protocol::format_poll 0 0 0 \
                        $hashes_done $last_hash7]
                }
            }]} {
                stop_and_close_owner $channel "ERR IO" POLL_IO
                return
            }
            puts $channel $response
        }
        STOP {
            if {[catch {stop_and_prove_idle}]} {
                stop_and_close_owner $channel "ERR IO" STOP_IO
                return
            }
            puts $channel "OK"
        }
        PING {
            puts $channel [vu9p_bs1_protocol::format_pong $build_id]
        }
        TEMP {
            if {[catch {set reading [master_slr_temp]}]} {
                stop_and_close_owner $channel "ERR IO" TEMP_IO
                return
            }
            puts $channel $reading
        }
        QUIT {
            stop_and_close_owner $channel "OK" QUIT
            set ::forever 1
            return
        }
    }
    flush $channel
}

proc on_accept {channel address remote_port} {
    if {[catch {fconfigure $channel -blocking 0 -buffering line \
            -encoding ascii -translation lf}]} {
        catch {close $channel}
        return
    }
    if {![vu9p_bs1_protocol::claim_owner $channel]} {
        catch {puts $channel "ERR BUSY"}
        catch {flush $channel}
        catch {close $channel}
        puts "BRIDGE_CLIENT_REJECTED $address:$remote_port reason=OWNER_BUSY"
        flush stdout
        return
    }
    fileevent $channel readable [list on_read $channel]
    puts "BRIDGE_OWNER $address:$remote_port"
    flush stdout
}

proc on_read {channel} {
    if {![vu9p_bs1_protocol::is_owner $channel]} {
        catch {close $channel}
        return
    }
    if {[catch {set count [gets $channel line]}]} {
        stop_and_close_owner $channel "" READ_ERROR
        return
    }
    if {$count >= 0} {
        if {[catch {handle_line $channel $line}]} {
            stop_and_close_owner $channel "" CALLBACK_ERROR
        }
        return
    }
    if {[eof $channel]} {
        stop_and_close_owner $channel "" EOF
        return
    }
    if {[catch {fblocked $channel} blocked] || !$blocked} {
        stop_and_close_owner $channel "" READ_ERROR
    }
}

set ::bridge_fatal_stop_failure 0
socket -server on_accept -myaddr 127.0.0.1 $port
puts "BRIDGE_READY port=$port target=$serial build_id=5a3d0001 protocol=BS1_EXACT_DIRECT_COUNTER_V1 telemetry=MASTER_SLR_ONLY sysmon_count=$bridge_sysmon_count"
flush stdout
vwait ::forever
if {[catch {stop_and_prove_idle}]} {
    set ::bridge_fatal_stop_failure 1
}
catch {close_hw_target}
catch {disconnect_hw_server}
catch {close_hw_manager}
if {$::bridge_fatal_stop_failure} {
    puts "BRIDGE_EXIT_FATAL reason=STOP_FAILURE_QUARANTINE"
    exit 1
}
puts "BRIDGE_EXIT"
