# Program the published BS1 image on one explicitly selected hardware target.
# Usage: Vivado Lab -mode batch -source program_bs1.tcl -tclargs SERIAL FILE.bit
# Requires sha256sum on PATH. Leaves BS1 stopped; start the bridge separately.
namespace eval ::bs1_program {
    variable bit_sha256 659ed0b524d3ed22567903e98fa26e9a7d0cfea87efb3e70c147db7442fe4cb2
    variable axi ""

    proc validate_serial {serial} {
        if {![regexp {^[A-Za-z0-9_-]{1,128}$} $serial]} {
            error "serial must be a literal hardware-target serial"
        }
    }

    proc verify_bit {path} {
        variable bit_sha256
        set path [file normalize $path]
        if {[file extension $path] ne ".bit" || ![file isfile $path] || [file size $path] <= 0} {
            error "expected a regular .bit file"
        }
        set tool [auto_execok sha256sum]
        if {$tool eq ""} { error "sha256sum is required on PATH" }
        if {[lindex [exec {*}$tool -- $path] 0] ne $bit_sha256} {
            error "bitstream is not the published BS1 image"
        }
        return $path
    }

    proc read32 {address} {
        variable axi
        set txn [create_hw_axi_txn -force bs1_read $axi -type read \
            -address [format %08x $address]]
        run_hw_axi $txn
        set data [get_property DATA $txn]
        if {![regexp {^[0-9a-fA-F]{8}$} $data]} { error "invalid AXI readback" }
        return [expr "0x$data"]
    }

    proc stop {} {
        variable axi
        set txn [create_hw_axi_txn -force bs1_stop $axi -type write \
            -address 00000058 -data 00000000]
        run_hw_axi $txn
        for {set poll 0} {$poll < 64} {incr poll} {
            if {([read32 0x5c] & 2) == 0} { return }
            after 1
        }
        error "BS1 STOP did not clear RUN"
    }

    proc telemetry {device} {
        set monitors [get_hw_sysmons -of_objects $device]
        if {[llength $monitors] != 1} { error "master-SLR monitor is not unique" }
        set monitor [lindex $monitors 0]
        refresh_hw_sysmon $monitor
        set temperature [get_property TEMPERATURE $monitor]
        set voltage [get_property VCCINT $monitor]
        foreach value [list $temperature $voltage] {
            if {![string is double -strict $value] || [regexp -nocase {nan|inf} $value]} {
                error "invalid telemetry"
            }
        }
        if {$temperature < 0 || $temperature >= 70 || $voltage < 0.680 || $voltage > 0.876} {
            error "temperature or VCCINT is outside the BS1 programming limits"
        }
        puts "BS1_SENSOR telemetry=MASTER_SLR_ONLY C=$temperature VCCINT=$voltage"
    }

    proc run {serial path} {
        variable axi
        validate_serial $serial
        set bit [verify_bit $path]
        set target_open 0
        set identified 0
        try {
            open_hw_manager
            connect_hw_server -url localhost:3121 -allow_non_jtag
            set targets [get_hw_targets *$serial]
            if {[llength $targets] != 1} { error "hardware target serial is not unique" }
            set target [lindex $targets 0]
            if {[file tail [get_property NAME $target]] ne $serial} {
                error "hardware target does not have the exact requested serial"
            }
            current_hw_target $target
            open_hw_target
            set target_open 1
            set devices [get_hw_devices xcvu9p*]
            if {[llength $devices] != 1} { error "VU9P is not unique on selected target" }
            set device [lindex $devices 0]
            current_hw_device $device
            refresh_hw_device $device -quiet
            telemetry $device
            verify_bit $bit
            set_property PROGRAM.FILE $bit $device
            program_hw_devices $device
            refresh_hw_device $device
            set axes [get_hw_axis]
            if {[llength $axes] != 1} { error "BS1 AXI is not unique" }
            set axi [lindex $axes 0]
            if {[read32 0x74] != 0x5a3d0001} { error "programmed build ID mismatch" }
            set identified 1
            stop
            telemetry $device
        } finally {
            set stop_rc 0
            if {$identified} { set stop_rc [catch {stop} stop_error] }
            if {$target_open} { catch {close_hw_target} }
            catch {disconnect_hw_server}
            catch {close_hw_manager}
            if {$stop_rc} { error "final STOP failed: $stop_error" }
        }
        puts "BS1_PROGRAMMED build_id=5a3d0001 stop_confirmed=1"
    }
}

if {[info exists ::BS1_PROGRAM_LIBRARY_ONLY] && $::BS1_PROGRAM_LIBRARY_ONLY} { return }
if {[llength $argv] != 2} { error "usage: program_bs1.tcl SERIAL FILE.bit" }
::bs1_program::run {*}$argv
