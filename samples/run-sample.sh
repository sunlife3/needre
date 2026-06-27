#!/usr/bin/env bash
# Build the sample payload + forker and trigger the detection.
#
#   1. compiles hello.c  -> /tmp/hello   (the payload needre should flag)
#   2. compiles forker.c -> /tmp/forker  (forks twice, then exec's /tmp/hello)
#   3. runs /tmp/forker
#
# Run `cargo run` (as root) in another terminal first, then run this script.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cc -O2 -o /tmp/hello  "$DIR/hello.c"
cc -O2 -o /tmp/forker "$DIR/forker.c"

echo "[run-sample] built /tmp/hello and /tmp/forker"
echo "[run-sample] launching /tmp/forker ..."
echo "---------------------------------------------"
/tmp/forker
echo "---------------------------------------------"
echo "[run-sample] done. Check needre output / /var/log/needre/needre_detect.log"
