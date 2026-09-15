#!/usr/bin/env bash
# Build and exercise the native host without opening USB or replacing a miner.
set -euo pipefail
umask 077

if [[ $# -ne 1 || $1 != /* ]]; then
    echo 'Usage: bash tools/build-host.sh /absolute/new-build-directory' >&2
    exit 2
fi
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
build_dir=$(realpath -m -- "$1")
case "$build_dir" in
    /|"$repo_dir"|"$repo_dir"/*)
        echo 'Choose a new build directory outside the source checkout.' >&2
        exit 2
        ;;
esac
if [[ -e "$build_dir" || -L "$build_dir" ]]; then
    echo 'Build directory already exists; choose a new name. Nothing overwritten.' >&2
    exit 2
fi
build_jobs=${SUPRMINER_BUILD_JOBS:-2}
if [[ ! $build_jobs =~ ^([1-9]|[1-5][0-9]|6[0-4])$ ]]; then
    echo 'SUPRMINER_BUILD_JOBS must be an integer from 1 to 64.' >&2
    exit 2
fi
mapfile -t test_targets < <(sed -nE \
    's/^add_executable\(([A-Za-z0-9_]+_test)[[:space:]].*/\1/p' \
    "$repo_dir/CMakeLists.txt")
if (( ${#test_targets[@]} == 0 )); then
    echo 'No explicit host regression targets found; refusing an untested build.' >&2
    exit 2
fi

mkdir -p -- "$build_dir"
# Keep assertions enabled in the regression programs, including release builds.
# The policy floor allows legacy project declarations with CMake 4.x; CMake
# versions that predate this variable may report it as an unused cache entry.
cmake -S "$repo_dir" -B "$build_dir" \
    -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_FLAGS_RELEASE=-O2 \
    -DCMAKE_CXX_FLAGS_RELEASE=-O2 \
    -DSUPRMINER_RUNTIME_OUTPUT_DIRECTORY="$build_dir/bin"
cmake --build "$build_dir" --parallel "$build_jobs" \
    --target suprminer-fpga "${test_targets[@]}"
ctest --test-dir "$build_dir" --output-on-failure
file "$build_dir/bin/suprminer-fpga"
sha256sum "$build_dir/bin/suprminer-fpga"
echo 'Native build and host tests passed. No USB device or production miner was touched.'
echo 'A different host/USB topology still requires attended hardware qualification.'
