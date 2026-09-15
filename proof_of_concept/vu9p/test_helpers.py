#!/usr/bin/env python3
"""Offline protocol tests. Tcl hardware/socket commands are mocked throughout."""
from pathlib import Path
import subprocess
import unittest

HERE = Path(__file__).resolve().parent

COMMON = r'''
proc assert {condition message} {
    if {![uplevel 1 [list expr $condition]]} { error "ASSERT: $message" }
}
proc rejects {script} { if {![catch {uplevel 1 $script}]} { error "expected rejection" } }
'''

# All native commands are implemented by this fixture. No hardware process,
# socket, or Vivado invocation is started by these tests.
HARDWARE = r'''
set ::events {}
set ::writes {}
set ::registers [dict create 0x74 0x5a3d0001 0x5c 0 0x68 25 0x6c 0 0x70 99 0x60 123 0x64 456]
set ::target_name localhost/mock/SERIAL_TEST
set ::targets target
set ::devices device
set ::axes axi
set ::monitors monitor
set ::temperature 40.0
set ::voltage 0.800
set ::fail_stop 0
set ::txn_counter 0
set ::transactions {}
proc open_hw_manager {} { lappend ::events open_manager }
proc connect_hw_server {args} { lappend ::events connect }
proc get_hw_targets {pattern} { return $::targets }
proc current_hw_target {target} { lappend ::events select_target }
proc open_hw_target {} { lappend ::events open_target }
proc close_hw_target {} { lappend ::events close_target }
proc get_hw_devices {pattern} { return $::devices }
proc current_hw_device {device} {}
proc refresh_hw_device {args} { lappend ::events refresh }
proc get_hw_sysmons {args} { return $::monitors }
proc refresh_hw_sysmon {monitor} { lappend ::events sensor }
proc get_hw_axis {} { return $::axes }
proc disconnect_hw_server {} { lappend ::events disconnect }
proc close_hw_manager {} { lappend ::events close_manager }
proc set_property {key value object} {
    assert {$key eq "PROGRAM.FILE"} "programming sets only PROGRAM.FILE"
    assert {[file extension $value] eq ".bit"} "vendor receives .bit suffix"
    lappend ::events set_bit
}
proc program_hw_devices {device} { lappend ::events program }
proc create_hw_axi_txn {args} {
    set type [lindex $args [expr {[lsearch -exact $args -type]+1}]]
    set address [lindex $args [expr {[lsearch -exact $args -address]+1}]]
    set key [format 0x%x [expr "0x$address"]]
    set id txn[incr ::txn_counter]
    if {$type eq "write"} {
        set data [lindex $args [expr {[lsearch -exact $args -data]+1}]]
        if {$key eq "0x58" && $data eq "00000000" && $::fail_stop} { error "STOP failed" }
        lappend ::writes [list $key $data]
        lappend ::events write:$key:$data
        if {$key eq "0x58"} { dict set ::registers 0x5c [expr {$data eq "00000001" ? 2 : 0}] }
    }
    dict set ::transactions $id $key
    return $id
}
proc run_hw_axi {args} {}
proc get_property {key object} {
    switch -- $key {
        NAME { return $::target_name }
        TEMPERATURE { return $::temperature }
        VCCINT { return $::voltage }
        VCCAUX { return 1.800 }
        VCCBRAM { return 0.800 }
        DATA {
            set address [dict get $::transactions $object]
            return [format %08x [dict get $::registers $address]]
        }
        default { error "unmocked property $key" }
    }
}
'''

BRIDGE = r'''
set argc 2
set argv {SERIAL_TEST 4711}
set ::messages {}
set ::closed {}
rename puts real_puts
proc puts {args} {
    if {[llength $args] == 2 && [string match client* [lindex $args 0]]} {
        lappend ::messages [list [lindex $args 0] [lindex $args 1]]
    } else { real_puts {*}$args }
}
rename close real_close
proc close {channel} {
    if {[string match client* $channel]} { lappend ::closed $channel } else { real_close $channel }
}
rename flush real_flush
proc flush {channel} { if {![string match client* $channel]} { real_flush $channel } }
rename fconfigure real_fconfigure
proc fconfigure {channel args} { if {![string match client* $channel]} { real_fconfigure $channel {*}$args } }
rename fileevent real_fileevent
proc fileevent {channel args} { if {![string match client* $channel]} { real_fileevent $channel {*}$args } }
rename socket real_socket
proc socket {args} {
    assert {$args eq {-server on_accept -myaddr 127.0.0.1 4711}} "local-only listener"
    lappend ::events listener
    return listener
}
rename vwait real_vwait
proc vwait {args} {}
source [file join $root vu9p_bs1_bridge.tcl]
set ::events {}
set ::writes {}
set ::messages {}
set ::closed {}
set ::bridge_fatal_stop_failure 0
set ::forever 0
'''

PROGRAM = r'''
set ::BS1_PROGRAM_LIBRARY_ONLY 1
source [file join $root program_bs1.tcl]
rename ::bs1_program::verify_bit ::bs1_program::real_verify_bit
proc ::bs1_program::verify_bit {path} {
    lappend ::events verify_bit
    return [file join $::root mock.bit]
}
'''


class Helpers(unittest.TestCase):
    def tcl(self, body, *, bridge=False, program=False, hardware=True):
        prelude = COMMON + (HARDWARE if hardware else "")
        prelude += BRIDGE if bridge else PROGRAM if program else ""
        script = "set root [lindex $argv 0]\n" + prelude + body + '\nputs TEST_PASS\n'
        # Passing the script through -c is not supported by tclsh. Use stdin,
        # assigning argv as a Tcl list without interpolating it into code.
        script = "set root [encoding convertfrom utf-8 [binary decode hex " + str(HERE).encode().hex() + "]]\n" + script.replace("set root [lindex $argv 0]\n", "", 1)
        wrapped = "if {[catch {\n" + script + "\n} message options]} { puts stderr $message; exit 1 }\n"
        result = subprocess.run(["tclsh"], input=wrapped, text=True, capture_output=True, timeout=10, cwd=HERE)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("TEST_PASS", result.stdout)

    def test_invocation_literal_target_and_exact_build(self):
        self.tcl(r'''
assert {[vu9p_bs1_protocol::require_exact_invocation SERIAL_TEST 4711 0x5a3d0001]} valid
foreach serial [list {} {*} {SERIAL[1]} {SERIAL;puts x} {SERIAL/other}] {
    rejects {vu9p_bs1_protocol::require_exact_invocation $serial 4711 0x5a3d0001}
}
foreach port {0 65536 -1 04711 1.2} {
    rejects {vu9p_bs1_protocol::require_exact_invocation SERIAL_TEST $port 0x5a3d0001}
}
rejects {vu9p_bs1_protocol::require_exact_invocation SERIAL_TEST 4711 0x5a3d0002}
rejects {vu9p_bs1_protocol::require_target_name localhost/mock/PREFIX_SERIAL_TEST SERIAL_TEST}
''', bridge=True)

    def test_work_register_order_and_endianness(self):
        self.tcl(r'''
set header [string repeat 0123456789abcdef 9]01234567
do_work $header 01020304 fffffffa
set expected {{0x58 00000000} {0x58 00000002} {0x58 00000000}}
for {set i 0} {$i < 19} {incr i} {
    lappend expected [list [format 0x%x [expr {$i*4}]] [expr {$i%2 ? "efcdab89" : "67452301"}]]
}
lappend expected {0x50 01020304} {0x54 fffffffa} {0x78 00000001} {0x58 00000001}
assert {$::writes eq $expected} "exact clear/header/target/base/mask/start order"
''', bridge=True)

    def test_counter_rollover_retry_and_exhaustion(self):
        self.tcl(r'''
set ::counter_words {0 4294967295 1 1 3 1}
set ::addresses {}
proc read_counter {address} {
    lappend ::addresses $address
    set value [lindex $::counter_words 0]
    set ::counter_words [lrange $::counter_words 1 end]
    return $value
}
assert {[vu9p_bs1_protocol::coherent_counter read_counter] == 4294967299} rollover
assert {$::addresses eq {0x6C 0x68 0x6C 0x6C 0x68 0x6C}} order
set ::counter_words [lrepeat 24 0]
proc bad_counter {address} { return [incr ::unstable] }
set ::unstable 0
rejects {vu9p_bs1_protocol::coherent_counter bad_counter}
assert {$::unstable == 24} bounded
''', bridge=True)

    def test_strict_protocol_and_poll_responses(self):
        self.tcl(r'''
assert {[vu9p_bs1_protocol::format_pong 0x5a3d0001] eq "PONG 5a3d0001"} pong
foreach request {{PING x} { POLL} {POLL } {QUIT;puts x} {WORK 00 00000000 00000000}} {
    rejects {vu9p_bs1_protocol::parse_request $request}
}
vu9p_bs1_protocol::claim_owner client1
handle_line client1 POLL
assert {[lindex $::messages end] eq {client1 {NONE 25 00000063}}} none
set ::messages {}
dict set ::registers 0x5c 1
handle_line client1 POLL
assert {[lindex $::messages end] eq {client1 {FOUND 0000007b 000001c8 25 00000063}}} found
assert {[lindex $::writes end] eq {0x78 00000001}} ack
''', bridge=True)

    def test_one_owner_busy_does_not_disturb_work(self):
        self.tcl(r'''
on_accept client1 127.0.0.1 50000
on_accept client2 127.0.0.1 50001
assert {[vu9p_bs1_protocol::is_owner client1]} "first owner retained"
assert {[lindex $::messages end] eq {client2 {ERR BUSY}}} busy
assert {$::writes eq {}} "no device write for second client"
assert {$::closed eq {client2}} "second closed"
''', bridge=True)

    def test_grammar_eof_callback_stop_and_quarantine(self):
        self.tcl(r'''
foreach reason {GRAMMAR WORK_IO POLL_IO STOP_IO TEMP_IO QUIT READ_ERROR CALLBACK_ERROR EOF} {
    vu9p_bs1_protocol::claim_owner client1
    set ::writes {}
    assert {[stop_and_close_owner client1 "" $reason] == 1} stopped
    assert {$::writes eq {{0x58 00000000}}} stop_order
    assert {![vu9p_bs1_protocol::is_owner client1]} released
}
vu9p_bs1_protocol::claim_owner client1
set ::fail_stop 1
assert {[stop_and_close_owner client1 OK EOF] == 0} "failure explicit"
assert {$::bridge_fatal_stop_failure && $::forever} quarantine
assert {[lindex $::messages end] eq {client1 {ERR IO}}} "no false OK"
''', bridge=True)

    def test_work_failure_never_acknowledges_success(self):
        self.tcl(r'''
vu9p_bs1_protocol::claim_owner client1
set ::fail_stop 1
handle_line client1 "WORK [string repeat 00 76] 00000000 00000000"
assert {[lindex $::messages end] eq {client1 {ERR IO}}} failure
assert {$::bridge_fatal_stop_failure} quarantined
''', bridge=True)

    def test_program_sequence_and_double_stop(self):
        self.tcl(r'''
::bs1_program::run SERIAL_TEST anything.bit
set i [lsearch -exact $::events program]
assert {$i > 0} programmed
assert {[lsearch -exact $::events sensor] < $i} "preprogram sensor"
assert {[llength [lsearch -all -exact $::events verify_bit]] == 2} "bit verified twice"
assert {$::writes eq {{0x58 00000000} {0x58 00000000}}} "only stop writes"
assert {[lindex $::events end] eq "close_manager"} cleanup
''', program=True)

    def test_program_rejects_hot_voltage_and_ambiguous_target(self):
        self.tcl(r'''
foreach temp {70 90 NaN Inf -1} {
    set ::temperature $temp; set ::events {}
    rejects {::bs1_program::run SERIAL_TEST anything.bit}
    assert {[lsearch -exact $::events program] < 0} "not programmed"
}
set ::temperature 40
foreach voltage {0.600 0.900 NaN} {
    set ::voltage $voltage; set ::events {}
    rejects {::bs1_program::run SERIAL_TEST anything.bit}
    assert {[lsearch -exact $::events program] < 0} "voltage rejected"
}
set ::voltage .800
foreach targets {{} {target other}} {
    set ::targets $targets; set ::events {}
    rejects {::bs1_program::run SERIAL_TEST anything.bit}
    assert {[lsearch -exact $::events program] < 0} "ambiguous rejected"
}
set ::targets target
set ::target_name localhost/mock/PREFIX_SERIAL_TEST
set ::events {}
rejects {::bs1_program::run SERIAL_TEST anything.bit}
assert {[lsearch -exact $::events program] < 0} "suffix alias rejected"
''', program=True)

    def test_program_rejects_wrong_build_and_stop_failure(self):
        self.tcl(r'''
dict set ::registers 0x74 0x5a3d0002
rejects {::bs1_program::run SERIAL_TEST anything.bit}
assert {$::writes eq {}} "no register write to wrong build"
dict set ::registers 0x74 0x5a3d0001
set ::fail_stop 1
rejects {::bs1_program::run SERIAL_TEST anything.bit}
assert {[lindex $::events end] eq "close_manager"} cleaned
''', program=True)

    def test_program_rejects_bit_hash_and_suffix_without_hardware(self):
        self.tcl(r'''
set ::BS1_PROGRAM_LIBRARY_ONLY 1
source [file join $root program_bs1.tcl]
set path [file join [pwd] wrong_public_test_[pid].bit]
set ch [open $path w]; puts $ch wrong; close $ch
try {
    rejects {::bs1_program::verify_bit $path}
    rejects {::bs1_program::verify_bit $path.other}
} finally { file delete $path }
''', hardware=False)


if __name__ == "__main__":
    unittest.main()
