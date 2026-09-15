cmake_minimum_required (VERSION 2.8)

project(suprminer-fpga C CXX)


# Confirm LIBUSB Has Been Installed
IF (NOT WIN32)
	find_package(PkgConfig)
	pkg_check_modules(PC_LIBUSB libusb-1.0)
ENDIF(NOT WIN32)
FIND_PATH( LIBUSB_INCLUDE_DIR libusb.h  PATHS ${PC_LIBUSB_INCLUDEDIR} ${PC_LIBUSB_INCLUDE_DIRS}  PATH_SUFFIXES include )
FIND_LIBRARY( LIBUSB_LIBRARIES NAMES usb-1.0  PATHS ${PC_LIBUSB_LIBDIR} ${PC_LIBUSB_LIBRARY_DIRS} PATH_SUFFIXES lib )

IF (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	SET(LIBUSB_FOUND TRUE)
ELSE (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
	SET(LIBUSB_FOUND FALSE)
ENDIF (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)

IF (LIBUSB_FOUND)
	message(STATUS "LIBUSB: Found")
ELSE (LIBUSB_FOUND)
	message(STATUS "LIBUSB: Not Found!")
ENDIF (LIBUSB_FOUND)


# Confirm CURL Has Been Installed
FIND_PATH( CURL_INCLUDE_DIR curl/curl.h  PATHS ${PC_CURL_INCLUDEDIR} ${PC_CURL_INCLUDE_DIRS}  PATH_SUFFIXES include )
FIND_LIBRARY( CURL_LIBRARIES NAMES curl  PATHS ${PC_CURL_LIBDIR} ${PC_CURL_LIBRARY_DIRS} PATH_SUFFIXES lib )

IF (CURL_INCLUDE_DIR AND CURL_LIBRARIES)
	SET(CURL_FOUND TRUE)
ELSE (CURL_INCLUDE_DIR AND CURL_LIBRARIES)
	SET(CURL_FOUND FALSE)
ENDIF (CURL_INCLUDE_DIR AND CURL_LIBRARIES)

IF (CURL_FOUND)
	message(STATUS "CURL: Found")
ELSE (CURL_FOUND)
	message(STATUS "CURL: Not Found!")
ENDIF (CURL_FOUND)


add_subdirectory(compat/jansson)

include_directories(${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/algo ${PROJECT_SOURCE_DIR}/compat/jansson ${CURL_INCLUDE_DIR} ${LIBUSB_INCLUDE_DIR})

set(SRC_LIST fpga-miner.c
		sha3_variant_state.c
		sha3_variant_file.c
		api.c
		fpgautils.c
		libztex.c
		libvu9p.c
		tui.c
		util.c
		./algo/blake256-8.c
		./algo/groestl.c
		./algo/sha3t.c
		./algo/myr-groestl.c
		./algo/sha2.c
		./algo/sph_blake.c
		./algo/sph_groestl.c
		./algo/blake3.c
		./algo/odohash.c
		./algo/odocrypt_wrapper.cpp
		./algo/odocrypt.cpp
		./algo/KeccakP-800-reference.c
	)
			
set(TARGET_NAME suprminer-fpga)

IF ( WIN32 )
	add_executable(${TARGET_NAME} ${SRC_LIST} ./compat/winansi.c)
ELSE ( WIN32 )
	add_executable(${TARGET_NAME} ${SRC_LIST})
ENDIF ( WIN32 )

target_link_libraries(${TARGET_NAME} pthread ${CURL_LIBRARIES} ${LIBUSB_LIBRARIES} jansson ncurses)

IF(WIN32)
	target_link_libraries(${TARGET_NAME} Ws2_32)
ENDIF(WIN32)

IF(UNIX)
	target_link_libraries(${TARGET_NAME} m)
ENDIF(UNIX)

# Keep the historical in-tree binary location by default, while allowing
# qualification builds to select an isolated output directory so they cannot
# overwrite the executable used by a live mining session.
set(SUPRMINER_RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}" CACHE PATH
    "Directory for the suprminer-fpga executable")
set_target_properties(${TARGET_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${SUPRMINER_RUNTIME_OUTPUT_DIRECTORY}")

# Pure host regression for SHA3T two-golden ordering/deduplication.  Keep this
# target out of normal miner builds so testing it cannot replace the production
# executable at ${PROJECT_SOURCE_DIR}/suprminer-fpga.
enable_testing()
add_executable(sha3_golden_dedup_test EXCLUDE_FROM_ALL sha3_golden_dedup_test.c)
add_test(NAME sha3_golden_dedup COMMAND sha3_golden_dedup_test)

# Pure host checks for the dormant ZTEX readback experiment's parser,
# classifier, retry schedule, and absolute board/lane phase arithmetic.
add_executable(ztex_rb_test_test EXCLUDE_FROM_ALL ztex_rb_test_test.c)
add_test(NAME ztex_rb_helpers COMMAND ztex_rb_test_test)

# Pure host regression for accepted-share fleet MH/s accounting and stale-rate
# lifecycle handling. EXCLUDE_FROM_ALL prevents tests from replacing or
# perturbing the production miner target during a normal build.
add_executable(hashrate_total_test EXCLUDE_FROM_ALL hashrate_total_test.c)
add_test(NAME hashrate_total COMMAND hashrate_total_test)

# Pure host regression for the SHA3T successor contract: nonce zero is checked
# on an immutable private copy and work identity includes the full target.
add_executable(sha3_nonce_zero_test EXCLUDE_FROM_ALL sha3_nonce_zero_test.c)
add_test(NAME sha3_nonce_zero COMMAND sha3_nonce_zero_test)

# Pure host regression for the move/restore/commit ownership transaction used
# to keep polling coherent when nonce-zero submission or USB publication fails.
add_executable(work_publish_guard_test EXCLUDE_FROM_ALL work_publish_guard_test.c)
add_test(NAME work_publish_guard COMMAND work_publish_guard_test)

# Allocation-failure regression for asynchronous work submission cloning.
add_executable(work_clone_checked_test EXCLUDE_FROM_ALL work_clone_checked_test.c)
add_test(NAME work_clone_checked COMMAND work_clone_checked_test)

# Pure codec regression for the versioned R34 ZTEX WORK/RESULT/ACK protocol.
add_executable(bc3_ztex_protocol_test EXCLUDE_FROM_ALL bc3_ztex_protocol_test.c)
add_test(NAME bc3_ztex_protocol COMMAND bc3_ztex_protocol_test)

# Pure state-machine regressions for R34 work lifetime/rate qualification and
# exact result deduplication/ACK authorization.
add_executable(bc3_ztex_session_test EXCLUDE_FROM_ALL bc3_ztex_session_test.c)
add_test(NAME bc3_ztex_session COMMAND bc3_ztex_session_test)
add_executable(bc3_ztex_result_test EXCLUDE_FROM_ALL bc3_ztex_result_test.c)
add_test(NAME bc3_ztex_result COMMAND bc3_ztex_result_test)

# Pure transport regression for explicit lane selection, exact 64-byte frame
# transfers, and immutable whole-pair retry of R34 work fragments.
add_executable(bc3_ztex_io_test EXCLUDE_FROM_ALL bc3_ztex_io_test.c)
add_test(NAME bc3_ztex_io COMMAND bc3_ztex_io_test)

# Pure packing regression for the R34 physical 80-byte work image: serialized
# header prefix, nonce exclusion, target byte order, and fragment reconstruction.
add_executable(bc3_ztex_work_test EXCLUDE_FROM_ALL bc3_ztex_work_test.c)
add_test(NAME bc3_ztex_work COMMAND bc3_ztex_work_test)

# Pure fail-closed parser regression for the explicit R34 BUILD_ID allowlist.
add_executable(bc3_ztex_gate_test EXCLUDE_FROM_ALL bc3_ztex_gate_test.c)
add_test(NAME bc3_ztex_gate COMMAND bc3_ztex_gate_test)

# Pure fail-closed parser regression for per-board FPGA selection and exact
# configuration ordering.  The parsed policy is shared by configuration and
# runtime initialization so a malformed selector cannot touch hardware.
add_executable(bc3_ztex_lane_policy_test EXCLUDE_FROM_ALL bc3_ztex_lane_policy_test.c)
add_test(NAME bc3_ztex_lane_policy COMMAND bc3_ztex_lane_policy_test)

# Pure diagnostic identity regression.  A nonzero generation makes nonce zero
# valid, while same-generation mutation and generation regression fail closed.
add_executable(bc3_ztex_progress_test EXCLUDE_FROM_ALL bc3_ztex_progress_test.c)
add_test(NAME bc3_ztex_progress COMMAND bc3_ztex_progress_test)

# Pure qualification-liveness regression. A loaded candidate cannot wait
# forever for first work or silently report zero forever, while legitimate
# drain/work/ACK/FIFO backpressure states remain governed by their own timers.
add_executable(bc3_ztex_liveness_test EXCLUDE_FROM_ALL bc3_ztex_liveness_test.c)
add_test(NAME bc3_ztex_liveness COMMAND bc3_ztex_liveness_test)

# Pure coordinator policy for candidate stop/failure monotonicity, exact typed
# workio token ownership, monotonic flush deadline, and final fail-closed status.
add_executable(bc3_ztex_shutdown_test EXCLUDE_FROM_ALL bc3_ztex_shutdown_test.c)
add_test(NAME bc3_ztex_shutdown COMMAND bc3_ztex_shutdown_test)

# Cross-layer policy regression for the long-gap completion-rate rebaseline,
# CPU-verified progress identity, and exact active-lane liveness refresh rules.
add_executable(bc3_ztex_runtime_policy_test EXCLUDE_FROM_ALL bc3_ztex_runtime_policy_test.c)
add_test(NAME bc3_ztex_runtime_policy COMMAND bc3_ztex_runtime_policy_test)

# Pure bounds/layout/height regression for transactionally decoded standard
# Stratum jobs. It exhausts all short prefixes before live parser integration.
add_executable(stratum_job_guard_test EXCLUDE_FROM_ALL stratum_job_guard_test.c)
add_test(NAME stratum_job_guard COMMAND stratum_job_guard_test)

# Pure socket authorization/generation state used to prevent shares or jobs
# from crossing reconnect boundaries.
add_executable(stratum_transport_guard_test EXCLUDE_FROM_ALL stratum_transport_guard_test.c)
add_test(NAME stratum_transport_guard COMMAND stratum_transport_guard_test)

# Bounded outstanding-submit accounting: exact IDs survive modulo collisions,
# full maps apply backpressure, and retired connection generations are reclaimed.
add_executable(stratum_submit_map_test EXCLUDE_FROM_ALL stratum_submit_map_test.c)
add_test(NAME stratum_submit_map COMMAND stratum_submit_map_test)

# Pure policy regression for fixed-bitstream SHA3T frequency ladders.  It
# proves safe initial fallback, sparse-rung traversal, zero-error probe-up and
# immediate step-down on any CPU-verified mismatch without touching USB.
add_executable(sha3_variant_ladder_test EXCLUDE_FROM_ALL sha3_variant_ladder_test.c)
add_test(NAME sha3_variant_ladder COMMAND sha3_variant_ladder_test)

# A successful FPGA configuration is provisional until that exact image has
# returned a clean CPU-verified diagnostic pair.  This pure regression proves
# the bounded commit/rollback decision without touching USB or bitstreams.
add_executable(sha3_variant_reconfig_test EXCLUDE_FROM_ALL
    sha3_variant_reconfig_test.c)
add_test(NAME sha3_variant_reconfig COMMAND sha3_variant_reconfig_test)

# Atomic persistence regression for per-lane fixed-bitstream assignments.
# The test uses only a private temporary directory and never touches USB or
# the production fleet_variant_state_v1.conf.
add_executable(sha3_variant_state_test EXCLUDE_FROM_ALL
    sha3_variant_state_test.c sha3_variant_state.c)
add_test(NAME sha3_variant_state COMMAND sha3_variant_state_test)

# Descriptor/schema regression for the final family-bound governor. This is
# deliberately not wired to live bitstreams until their exact qualified names
# and SHA-256 identities exist.
add_executable(sha3_variant_family_test EXCLUDE_FROM_ALL
    sha3_variant_family_test.c)
add_test(NAME sha3_variant_family COMMAND sha3_variant_family_test)

# SHA-256 binding for fixed-image catalog entries. The test hashes only files
# in a private temporary directory and never opens a production bitstream.
add_executable(sha3_variant_file_test EXCLUDE_FROM_ALL
    sha3_variant_file_test.c sha3_variant_file.c algo/sha2.c)
add_test(NAME sha3_variant_file COMMAND sha3_variant_file_test)

# The checked-in catalog contains only a synthetic descriptor.
# Automatic frequency selection remains disabled.
add_executable(sha3_variant_catalog_test EXCLUDE_FROM_ALL
    sha3_variant_catalog_test.c)
add_test(NAME sha3_variant_catalog COMMAND sha3_variant_catalog_test)

# BS1 policy and transport tests use no USB or external network connections.
add_executable(vu9p_bs1_policy_test EXCLUDE_FROM_ALL vu9p_bs1_policy_test.c)
add_test(NAME vu9p_bs1_policy COMMAND vu9p_bs1_policy_test)
add_executable(libvu9p_test EXCLUDE_FROM_ALL libvu9p_test.c libvu9p.c)
target_link_libraries(libvu9p_test pthread)
add_test(NAME vu9p_transport COMMAND libvu9p_test)

# Keep the existing pre-USB heartbeat option gate in the standard suite.
add_executable(bc3_ztex_heartbeat_policy_test EXCLUDE_FROM_ALL bc3_ztex_heartbeat_policy_test.c)
add_test(NAME bc3_ztex_heartbeat_policy COMMAND bc3_ztex_heartbeat_policy_test)

# Exercise actual worker and CLI wiring without opening physical devices.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_program(SUPRMINER_PYTHON3 NAMES python3)
    if(SUPRMINER_PYTHON3)
        add_test(NAME vu9p_worker_mock COMMAND ${SUPRMINER_PYTHON3} -I -B
            ${PROJECT_SOURCE_DIR}/tools/test-vu9p-worker.py ${PROJECT_SOURCE_DIR})
        add_test(NAME vu9p_cli COMMAND ${SUPRMINER_PYTHON3} -I -B
            ${PROJECT_SOURCE_DIR}/tools/test-vu9p-cli.py $<TARGET_FILE:suprminer-fpga>)
        add_test(NAME vu9p_miner_smoke COMMAND ${SUPRMINER_PYTHON3} -I -B
            ${PROJECT_SOURCE_DIR}/tools/test-vu9p-smoke.py $<TARGET_FILE:suprminer-fpga>)
        find_program(SUPRMINER_TCLSH NAMES tclsh)
        if(SUPRMINER_TCLSH)
            add_test(NAME vu9p_tcl_helpers COMMAND ${SUPRMINER_PYTHON3} -I -B
                ${PROJECT_SOURCE_DIR}/proof_of_concept/vu9p/test_helpers.py)
        endif()
    endif()
endif()
