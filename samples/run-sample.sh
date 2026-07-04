#!/usr/bin/env bash
# Build the sample payload + forker and trigger a detection from every
# configured monitored directory.
#
#   1. compiles forker.c -> /tmp/forker (forks twice, then exec's a payload)
#   2. for each directory in $DIRS:
#        compiles hello.c -> <dir>/hello   (the payload needre should flag)
#        runs /tmp/forker <dir>/hello
#
# Directories default to the configured set (/tmp /dev/shm /var/tmp); override
# by passing them as arguments:  ./run-sample.sh /tmp /dev/shm
#
# Run `cargo run` (as root) in another terminal first, then run this script.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIRS=("${@:-/tmp /dev/shm /var/tmp}")
# Re-split the default string into words if no args were given.
if [ "$#" -eq 0 ]; then DIRS=(/tmp /dev/shm /var/tmp); fi

cc -O2 -o /tmp/forker "$DIR/forker.c"
echo "[run-sample] built /tmp/forker"

for d in "${DIRS[@]}"; do
    mkdir -p "$d"
    cc -O2 -o "$d/hello" "$DIR/hello.c"
    echo "[run-sample] built $d/hello — launching /tmp/forker $d/hello ..."
    echo "---------------------------------------------"
    /tmp/forker "$d/hello"
    echo "---------------------------------------------"
done

echo "[run-sample] done. Check needre output / /var/log/needre/needre_detect.log"
