#!/bin/sh
# Connection-level experiments for the revised paper (run as root on Linux).
# Applies tc netem to the loopback interface, captures first flights with
# tcpdump, and runs the TestConn* measurements for obfs4 and pqobfs.
set -eu
OUT=${OUT:-/tmp/pqm}
REPO=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$OUT"
ip link set lo mtu 1500
ethtool -K lo tso off gso off gro off >/dev/null 2>&1 || true

run() { # label N one-way-delay-ms
  label=$1; n=$2; d=${3:-0}
  (cd "$REPO" && PQM_OUT="$OUT" PQM_LABEL="$label" PQM_N="$n" PQM_DELAY_MS="$d" \
    go test -tags "pqobfs measure" -run TestConnLatency -v -count=1 -timeout 3600s \
    ./transports/obfs4/) | grep -vE "^=== RUN"
}

# 1. Baseline with packet capture of every first flight.
tcpdump -i lo -nn -s 128 -w "$OUT/firstflights.pcap" \
  'tcp portrange 20100-20400' >/dev/null 2>&1 &
TCPDUMP=$!
sleep 1
run rtt0 500
sleep 1; kill $TCPDUMP; wait $TCPDUMP 2>/dev/null || true

# 2. Bridge throughput (no netem).
for c in 2 8 32; do
(cd "$REPO" && PQM_OUT="$OUT" PQM_CONC=$c PQM_DUR=10 PQM_POOL=8000 go test -tags "pqobfs measure" \
  -run TestConnThroughput -v -count=1 -timeout 1200s ./transports/obfs4/) | grep -vE "^=== RUN"
done

# 3. Emulated paths. Kernel netem is unavailable on the measurement VM, so
#    the harness inserts a userspace relay that delays every chunk by the
#    one-way delay in each direction (RTT = 2 x delay). Loss is not emulated.
run rtt50 200 25
run rtt150 100 75
run rtt300 60 150
