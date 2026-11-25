#!/bin/sh
# Private Tor network (Chutney) with one pqobfs (or obfs4) bridge, one bridge
# client, four relays and five authorities, all on localhost. For each
# configuration: build the network, bootstrap the bridge client through the
# bridge, and push data through a circuit with `chutney verify`.
#
# Needs: tor + tor-gencert, a patched Chutney (chutney-pqobfs.patch, adds the
# pqobfs transport), and lyrebird built with -tags pqobfs at /usr/local/bin.
#   usage: run_private_tor.sh <label> <network> [encoding] [hybrid] [cover]
set -u
LABEL=$1; NET=$2; ENC=${3:-rejection}; HYB=${4:-0}; COVER=${5:-fixed}
D=/tmp/chutney-$LABEL; OUT=${OUT:-/tmp/pqm/privatetor}
mkdir -p "$OUT"; rm -rf "$D"; mkdir -p "$D"
chutney --data-dir "$D" init --net "$NET" >/dev/null 2>&1 || exit 1
# Node directories are created by `configure`; the network's composition
# (5 authorities, 4 relays, bridge, client, bridge client) fixes their names.
BR="$D/nodes/009br"; BC="$D/nodes/011bc"
if [ "$NET" = bridges-pqobfs ]; then
  # Pre-seed the bridge's state with the requested suite and cover policy.
  mkdir -p "$BR/pt_state"
  python3 - "$BR/pt_state/pqobfs_state.json" "$ENC" "$HYB" "$COVER" <<'PY'
import json, os, secrets, sys, subprocess
p, enc, hyb, cover = sys.argv[1:]
js = {"node-id": secrets.token_hex(20), "mlkem-seed": secrets.token_hex(64),
      "drbg-seed": secrets.token_hex(24), "iat-mode": 0, "cover": cover,
      "encoding": enc, "hybrid": hyb,
      # X25519 private key: 32 random bytes (clamped by the X25519 function).
      "x25519-key": secrets.token_hex(32)}
json.dump(js, open(p, "w"))
PY
fi
chutney --data-dir "$D" configure >/dev/null 2>&1 || exit 1
[ -f "$BR/pt_state/pqobfs_bridgekeys.txt" ] && mkdir -p "$BC/pt_state" && cp "$BR/pt_state/pqobfs_bridgekeys.txt" "$BC/pt_state/"
for ph in 1 2 3; do
  chutney --data-dir "$D" start --launch-phase $ph >/dev/null 2>&1
  timeout 150 chutney --data-dir "$D" wait_for_bootstrap >/dev/null 2>&1
done
timeout 150 chutney --data-dir "$D" verify > "$OUT/$LABEL.verify.log" 2>&1; V=$?
grep -h "Bootstrapped\|bridge descriptor" "$BC/notice.log" > "$OUT/$LABEL.bootstrap.log"
grep -h "^Bridge" "$BC/torrc" > "$OUT/$LABEL.bridgeline.txt"
chutney --data-dir "$D" stop >/dev/null 2>&1
echo "$LABEL verify_exit=$V $(grep -c 'Bootstrapped 100' "$OUT/$LABEL.bootstrap.log") $(grep 'Single Stream' "$OUT/$LABEL.verify.log")"
