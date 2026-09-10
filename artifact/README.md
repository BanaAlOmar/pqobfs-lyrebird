# Reproducibility artifact

Everything needed to reproduce the measurements and the cross-implementation
results reported in the pq-obfs paper. All code lives in the tree; this
directory holds the measurement outputs and the Rust-side interop harness.

## What is implemented

The `pqobfs` build tag enables a complete pq-obfs handshake (Günther, Stebila
and Veitch, CCS 2024) with the complete ML-Kemeleon obfuscated KEM
(draft-irtf-cfrg-kemeleon), on top of the unmodified obfs4 outer structure:

    ClientHello: c_S' (1252) | ek' (1156) | M_C (16) | pad -> 4096 | MAC_C (16)
    ServerHello: c_e' (1252) | AUTH (32)  | M_S (16) | pad -> 4096 | MAC_S (16)

* `c_S'` is the Kemeleon-encoded encapsulation to the bridge's static ML-KEM-768
  key, yielding `K_S`, which only a holder of `sk_S` can recover.
* `ek'` is the Kemeleon-encoded client ephemeral encapsulation key.
* `c_e'` is the Kemeleon-encoded encapsulation to `ek`, yielding `K_e`.
* Marks and MACs are keyed from `HMAC(t_mac_key, K_S || NodeID)`.
* `KEY_SEED` and `AUTH` derive from
  `K_S || K_e || NodeID || c_S' || ek' || c_e' || ProtoID`.

Every field on the wire is a Kemeleon representative, so no transmitted byte
carries ML-KEM lattice structure.

## Running the tests

    go test ./...                          # default build, unchanged
    go test -tags pqobfs ./...             # 12 unit + 8 integration tests

## Reproducing the measurements

Set the loopback MTU to 1500 and disable segmentation offload, then:

    tcpdump -i lo -nn -s 96 -w handshakes.pcap \
        'tcp port 41100 or tcp port 41200' &
    go test -tags "pqobfs measure" -run TestPQMeasure -v -count=1 \
        ./transports/obfs4/

Results are written to `$PQ_MEASURE_DIR` (default `/tmp/pqmeasure`). The JSON
files in this directory are one such run on a 2.8 GHz Intel Xeon vCPU with
Go 1.24.7 and CIRCL v1.5.0:

| file | contents |
| --- | --- |
| `primitives.json` | per-primitive costs; key acceptance 0.825, ciphertext acceptance 0.766 |
| `handshake_inprocess.json` | handshake CPU cost, classical vs pq |
| `handshake_tcp.json` | handshake latency over a TCP loopback socket |
| `bytestats.json` | popcount, MSB and byte-chi-square over 1,000 keys |
| `ciphertext_stats.json` | matched-filter detector over 1,000 ciphertexts |

The capture shows every pq-obfs connection as three TCP segments of
(1448, 1448, 1216) bytes in both directions, totalling 4112.

## Cross-implementation validation

`kemeleon-interop.rs` is an example program for the Rust reference
implementation (github.com/jmwample/kemeleon, v0.1.0-rc.1, commit cb139f8).
The crate's pinned `ml-kem` git dependency no longer builds against the newest
`kem` pre-release, so pin it first:

    git clone https://github.com/jmwample/kemeleon && cd kemeleon
    sed -i 's|^kem = "0.3.0-pre.0"|kem = "=0.3.0-pre.0"|' Cargo.toml
    cp .../kemeleon-interop.rs examples/interop.rs
    cargo build --release --example interop
    ./target/release/examples/interop gen 200 > rust_vectors.json

Then, in this tree:

    KEMELEON_VECTORS=rust_vectors.json \
      go test -tags interop -run TestInterop -v ./internal/mlkem_kemeleon/

    KEMELEON_GO_OUT=go_vectors.json \
      go test -tags interop -run TestInteropEmitGoEncodings \
      ./internal/mlkem_kemeleon/
    ./target/release/examples/interop decode < go_vectors.json

### Result

Reference -> this implementation: 200/200 encapsulation keys and 200/200
ciphertexts decode to the exact FIPS 203 bytes. Re-encoding the reference's
keys with this encoder reproduces its accumulator and seed bit for bit, the
only difference being the high-order bits both sides fill with randomness.

This implementation -> reference: 200/200 encapsulation keys decode correctly;
4/200 ciphertexts do. The cause is a deviation in the reference. The draft ends
`VectorEncodeR` with `IntegerRandomizeUnused` and begins `VectorDecodeR` with
`IntegerClearUnused`, and `EncodeCtxtR` invokes `VectorEncodeR`, so the six
unused high-order bits of an ML-KEM-768 ciphertext accumulator must be random.
The reference does this for encapsulation keys but not for ciphertexts: all 200
of its ciphertexts have those bits zero (one pattern out of 64) against 62
distinct patterns in 200 of ours, and its decoder does not mask them, so it
accepts a draft-conformant ciphertext only when the random bits happen to be
zero — 4 of 200, against the 3.1 expected at 1/64.

Security impact: six fixed-zero bits at a known offset in every encoded
ciphertext are a distinguisher with full recall and a 1/64 false-positive rate
per message (1/4096 over two messages), stronger than the 3.64-sigma
matched-filter attack the ciphertext encoding exists to defeat. This is the
same class of flaw as Fifield's 2022 finding in obfs4proxy's Elligator 2 path.
It should be reported upstream before the encoding is deployed.
`TestInteropReferenceCiphertextUnusedBits` documents it and skips if a future
version fixes it.

## Not included here

The reference and Go vector files (`rust_vectors.json`, `go_vectors.json`,
about 1.9 MB each) and the packet capture are regenerated by the commands
above and are omitted to keep the repository small.
