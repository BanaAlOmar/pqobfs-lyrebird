#!/bin/sh
# Real-network experiment: bridge on one host, client on another.
#
# On the BRIDGE host (any Linux VPS, Go 1.24+, TCP ports PORTBASE+100..400 open):
#   ./artifact/vps/run_vps.sh bridge            # serves for 2 hours
# Copy /tmp/pqm-vps/bridges.json to the client host, then on the CLIENT host:
#   sudo ./artifact/vps/run_vps.sh client <bridge-ip> <label> [loss%]
# e.g. label "fra-sgp". Run once per client region. Results go to
# /tmp/pqm-vps/<label>/; send that directory back to regenerate the paper's
# figures (artifact/analysis/*.py read the same JSON/pcap formats).
#
# The client side optionally adds real kernel netem loss on its egress
# interface (needs root); delay comes from the real path.
set -eu
MODE=${1:?bridge|client}
OUT=/tmp/pqm-vps
PORTBASE=${PORTBASE:-20000}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"
case "$MODE" in
bridge)
  mkdir -p "$OUT"
  PQM_OUT="$OUT" PQM_SERVE_SECONDS=${SERVE_SECONDS:-7200} PQM_PORTBASE=$PORTBASE \
    go test -tags "pqobfs measure" -run TestConnServe -count=1 -timeout 0 -v ./transports/obfs4/
  ;;
client)
  HOST=${2:?bridge ip}; LABEL=${3:?label}; LOSS=${4:-0}
  D="$OUT/$LABEL"; mkdir -p "$D"
  IF=$(ip route get "$HOST" | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}')
  if [ "$LOSS" != 0 ]; then tc qdisc add dev "$IF" root netem loss "${LOSS}%"; fi
  tcpdump -i "$IF" -nn -s 128 -w "$D/firstflights.pcap" \
    "host $HOST and tcp portrange $((PORTBASE+100))-$((PORTBASE+400))" >/dev/null 2>&1 &
  TD=$!; sleep 1
  PQM_OUT="$D" PQM_BRIDGES="$OUT/bridges.json" PQM_REMOTE_HOST="$HOST" PQM_LABEL="$LABEL" \
    PQM_N=${N:-300} PQM_PORTBASE=$PORTBASE \
    go test -tags "pqobfs measure" -run TestConnLatency -count=1 -timeout 0 -v ./transports/obfs4/ | grep -E "median|FAIL"
  kill $TD; wait $TD 2>/dev/null || true
  if [ "$LOSS" != 0 ]; then tc qdisc del dev "$IF" root; fi
  ping -c 20 "$HOST" > "$D/ping.txt" 2>&1 || true
  echo "results in $D"
  ;;
esac
