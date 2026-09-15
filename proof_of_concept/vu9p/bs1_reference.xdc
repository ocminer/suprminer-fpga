# Fixed BCU1525 reference clock/pins; no geometry or floorplan constraints.
set_property PACKAGE_PIN AY37 [get_ports sysclk_p]
set_property PACKAGE_PIN AY38 [get_ports sysclk_n]
set_property IOSTANDARD LVDS [get_ports {sysclk_p sysclk_n}]
set_property DQS_BIAS TRUE [get_ports {sysclk_p sysclk_n}]
create_clock -period 3.333 -name sysclk [get_ports sysclk_p]
set_property CFGBVS GND [current_design]
set_property CONFIG_VOLTAGE 1.8 [current_design]

# Retained historical BS1 clock separation; this is not a new CDC signoff.
set core_c [get_clocks -of_objects [get_pins mmcm_i/CLKOUT0]]
set ctrl_c [get_clocks -of_objects [get_pins mmcm_i/CLKOUT1]]
set_clock_groups -asynchronous -group $core_c -group $ctrl_c
set core_period [get_property PERIOD $core_c]
set ctrl_period [get_property PERIOD $ctrl_c]
set_max_delay -datapath_only -from $ctrl_c -to $core_c $core_period
set_max_delay -datapath_only -from $core_c -to $ctrl_c $ctrl_period
set_property BITSTREAM.GENERAL.COMPRESS TRUE [current_design]
set_property BITSTREAM.CONFIG.OVERTEMPSHUTDOWN ENABLE [current_design]
