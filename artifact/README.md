# Reproducibility artifact

Archived at Zenodo: https://doi.org/10.5281/zenodo.24521450 (version 1.0.1).

Everything needed to regenerate every number, table and figure in the paper.
All experiments run on Linux with Go 1.24, Python 3.11+ (`numpy scipy
matplotlib dpkt kyber-py==1.2.0`) and, for the cross-implementation test,
Rust 1.81+. Packet capture needs root (tcpdump, ethtool).

| Step | Command | Output |
|---|---|---|
| 1. Corpora (10,000 keys/ciphertexts per implementation) | `python3 artifact/analysis/gen_kyberpy.py 10000 /tmp/corpus/ek_raw_kyberpy.bin` then `CORPUS_DIR=/tmp/corpus CORPUS_N=10000 go test -tags corpus -run TestCorpus ./internal/mlkem_kemeleon/` | `/tmp/corpus/*.bin`, `acceptance.json` |
| 2. Rust reference vectors | see "Cross-implementation validation" below; `interop gen 1000 > /tmp/corpus/rust_vectors.json` | `rust_vectors.json` |
| 3. Detection statistics, GFW rules, six-bit test, ROC | `python3 artifact/analysis/stats.py` | `results/stats.json` |
| 4. SP 800-22 tests | `CORPUS_N=33000` corpus in `/tmp/corpus_big`, then `CORPUS_DIR=/tmp/corpus_big NIST_SEQS=300 python3 artifact/analysis/nist.py` | `results/nist.json` |
| 5. Connection experiments (latency, capture, throughput) | `sudo ./artifact/run_conn_experiments.sh` | `/tmp/pqm/conn_latency_*.json`, `firstflights.pcap`, `throughput_*.json` |
| 6. Active probing | `go test -tags "pqobfs measure" -run TestActiveProbing -v ./transports/obfs4/` | `active_probing.json` |
| 7. Length analysis | `python3 artifact/analysis/lengths.py` | `results/lengths.json` |
| 8. Codec benchmarks | `go test -tags pqobfs -run XXX -bench Radix -benchtime 5000x -count 5 ./internal/mlkem_kemeleon/ > /tmp/pqm/radix_bench.txt` | `radix_bench.txt` |
| 9. Handshake computation, original vs revised | `PQ_MEASURE_DIR=/tmp/pqm/<before|after|final> go test -tags "pqobfs measure" -run 'TestPQMeasurePrimitives|TestPQMeasureHandshakeInProcess' ./transports/obfs4/` on the original commit (`9324cd3`), on the codec-only state, and on this branch | `primitives.json`, `handshake_inprocess.json` |
| 10. AVX-SSE transition | `go test -tags measure -run TestMeasureAVXTransition -v ./internal/mlkem_kemeleon/` | `vzeroupper.json` |
| 11. Figures and LaTeX macros | `python3 artifact/analysis/figs.py && python3 artifact/analysis/make_macros.py` | `figs/*.pdf`, `results.tex`, `nist_table.tex` |

Kernel `netem` was not available on the measurement VM, so
`run_conn_experiments.sh` emulates round-trip time with a userspace delay relay
built into the harness (`PQM_DELAY_MS`); loss is not emulated. On a host with
netem, the same tests can be run against `tc qdisc ... netem delay` instead.

## Cross-implementation validation

`kemeleon-interop.rs` is an example program for the Rust reference
implementation (github.com/jmwample/kemeleon, v0.1.0-rc.1, commit cb139f8,
still the latest crates.io release in November 2026). Pin the `kem`
pre-release first:

    git clone https://github.com/jmwample/kemeleon && cd kemeleon
    sed -i 's|^kem = "0.3.0-pre.0"|kem = "=0.3.0-pre.0"|' Cargo.toml
    mkdir -p examples && cp .../kemeleon-interop.rs examples/interop.rs
    cargo build --release --example interop
    ./target/release/examples/interop gen 1000 > rust_vectors.json

    KEMELEON_VECTORS=rust_vectors.json \
      go test -tags interop -run TestInterop -v ./internal/mlkem_kemeleon/

Result: the reference leaves the six unused high-order accumulator bits of
every ciphertext at zero (1,000 of 1,000), where the specification requires
fresh randomness; its key path is conformant. See the paper, Section 7, and
`upstream/kemeleon-ciphertext-unused-bits.md`.

## Files in this directory from the first submission

`handshake_tcp.json`, `handshake_inprocess.json`, `ciphertext_stats.json`,
`bytestats.json`, `primitives.json` are the measurements of the first
submission (original implementation, 2.8 GHz Xeon). The revised paper uses
the outputs of the steps above.

## Additions in the second revision

| Path | What it is | How to run |
|---|---|---|
| `../doc/pqobfs-spec.txt` | Draft normative pqobfs specification (wire format, suites, bridge lines with `pq-id`, cover policies, encoding requirements) | read |
| `vectors/kemeleon768_decode_vectors.json` | 520 ML-KEM-768 decoding vectors; rejection-encoded keys and ciphertexts with all 64 unused-bit values, plus default-encoded objects | `go test -run TestDecodeVectors -v ./internal/mlkem_kemeleon/` (regenerate: `go test -tags vectors -run TestWriteVectors ./internal/mlkem_kemeleon/`) |
| `conformance/kemeleon_conformance.py` | Output-distribution test of any ML-KEM encoder (range, MSB, matched filter, byte chi-square, per-position, unused bits) | `python3 conformance/kemeleon_conformance.py --kind ct --params 768 --encoding rejection sample.bin` |
| `privatetor/` | Chutney network files and patch; boots a private Tor network with a pqobfs bridge and bridge client | `privatetor/run_private_tor.sh` (needs tor and chutney) |
| `vps/run_vps.sh` | Repeats the connection measurements between two Internet hosts (bridge on one, client on the other) | see the script header |
| `formal/pqobfs.pv` | ProVerif model of the handshake (secrecy and authentication queries); **not yet verified** | `proverif formal/pqobfs.pv` |
| `results-arm/` | Measurements on an Apple Silicon arm64 VM | see its README |
| `analysis/censor_sim.py` | Trained classifier, response-delay channel and stateful per-bridge censor on the first-flight capture | `PCAP=firstflights.pcap python3 analysis/censor_sim.py` |
| `analysis/kemeleon_generic.py` | Wire-image surfaces for ML-KEM-512/768/1024 | `python3 analysis/kemeleon_generic.py` |
| `../cmd/pqobfs-rotate` | Rotates a bridge's long-term key, keeping the old one for a grace period | `go run -tags pqobfs ./cmd/pqobfs-rotate -state <dir> -grace 720h` |
| `../.github/workflows/pqobfs.yml` | CI: vet, tests, 30 s fuzzing per target, conformance tool, decoding vectors | GitHub Actions |

Measurement-only tests use build tags `measure` (`TestMeasureJunkCost`, `TestMeasureEncapTiming`, connection experiments) and `corpus`.

## Additions in the third revision: coordinated cover and Drivel

| Path | What it is | How to run |
|---|---|---|
| `../transports/obfs4/cover_policy.go` | Coordinated cover: response-time normalization (`resp-delay=target=T,jitter=J`, in µs, anchored at the first byte of the client's flight, precise wait) and the obfs4 padding floor (`pad-floor=C:S`, backward compatible) | `go test -run 'TestParseCoverPolicies|TestPadFloor|TestRespDelay' -v ./transports/obfs4/` |
| `analysis/defense_sim.py` | Classifier and per-bridge censor against nine bridge configurations (baselines, pq-only jitter, coordinated, light), five replicates of 500 connections each | `PQM_SET=defense` runs of step 5 (loopback MTU 1500, offloads off, as in `run_conn_experiments.sh`), captured as `/tmp/pqm/defense_r{1..5}.pcap` (`tcpdump -i lo -nn -s 128 'tcp portrange 20100-21100'`), then `python3 analysis/defense_sim.py` → `results/defense.json` |
| `analysis/perbridge_robust.py` | Per-bridge censor on the pooled replicates (2,500 connections per configuration, 20 splits, 2,000 bridges of k distinct connections) with a permutation null, a feature ablation at k = 20 and the bridge-length means per replicate | after `defense_sim.py`: `python3 analysis/perbridge_robust.py` → `results/defense_perbridge.json` |
| `drivel/kemeleon-eval/main.go` | Encodes 10,000 ML-KEM-768/1024 ciphertexts with Drivel's Kemeleon encoder (lyrebird-drivel `21c0d06`) and checks every round trip | copy to `cmd/kemeleon-eval/` in the Drivel tree; `go run ./cmd/kemeleon-eval /tmp/drivel 10000` |
| `analysis/drivel_eval.py` | Conformance tests on the Drivel encodings, as shipped and with a byte-aligned t; Drivel handshake length policy from its source constants | For `/tmp/drivel_fix`, apply the fix described in `upstream/drivel-kemeleon-top-bits.md` (`t = 8*kemeleonCtxtLength - b` in `vectorEncodeNR`) to a second Drivel tree and run `kemeleon-eval` there with output `/tmp/drivel_fix`; then `DRIVEL_DIR=/tmp/drivel DRIVEL_FIX_DIR=/tmp/drivel_fix python3 analysis/drivel_eval.py` → `results/drivel.json` |
| `upstream/drivel-kemeleon-top-bits.md` | Report for lyrebird-drivel: fixed zero top bits in c_S and a wire-compatible fix | read |

## Additions in the fourth revision: statistical validation and robustness

| Path | What it is | How to run |
|---|---|---|
| `analysis/defense_stats.py` | Run holdout (train runs 1-3, test 4-5), leave-one-run-out, bootstrap CIs, equivalence test (margin 0.05), four classifiers, per-bridge censor with run separation and null | `python3 analysis/defense_stats.py` → `results/defense_stats.json` |
| `../cmd/pqm-jitter-relay` | Separate-process relay with exponential, order-preserving per-chunk delay and a precise wait | `go build ./cmd/pqm-jitter-relay` |
| `PQM_SET=robust` / `PQM_SET=slow` in `pq_conn_measure_test.go` | Undefended and coordinated bridges for the jitter and load runs; normal and 4x-slower hosts (`PQM_SLOW`) at T = 2 and 6 ms | see `analysis/robust_eval.py` header; loopback MTU 1500 and offloads off in the same shell as the capture |
| `analysis/robust_eval.py` | Jitter, CPU-load and slow-host analyses, leave-one-run-out over four runs, with per-bridge nulls | `ROBUST_DIR=/tmp/pqm/robust python3 analysis/robust_eval.py` → `results/robust.json` |
| `analysis/extra_stats.py` | Effect sizes for payload tests, joint and serial tests of the six unused bits, padding-floor adoption curve, ciphertext acceptance derivation | `python3 analysis/extra_stats.py` → `results/extra_stats.json` |

## Map from the paper to scripts and result files

All numbers enter the paper through `analysis/make_macros.py` (writes `results.tex` and `nist_table.tex`); all figures come from `analysis/figs.py`.

| Paper item | Script | Result file(s) |
|---|---|---|
| Table 2 (parameter sets) | `analysis/kemeleon_generic.py` | `results/paramsets.json` |
| Table 4, Figures 4 and 5 (payload tests, distributions, ROC) | `analysis/stats.py` | `results/stats.json`, `popcount.npz`, `roc.npz` |
| Table 5, Figure 6 (lengths) | `analysis/lengths.py` | `results/lengths.json`, `flights.npz` |
| Table 6 (classifier, per-bridge censor) and Supplementary Fig. S2 | `analysis/censor_sim.py` | `results/censor_sim.json` |
| Table 7, Figure 7 (coordinated cover) and Supplementary Section S5 | `analysis/defense_sim.py`, `analysis/defense_stats.py`, `analysis/perbridge_robust.py` | `results/defense.json`, `defense_stats.json`, `defense_perbridge.json`, `defense_features.npz` |
| Table 8, Figure 8 (robustness: load; jitter and slow hosts) | `analysis/robust_eval.py` | `results/robust.json` |
| Effect sizes, six-bit independence, adoption share, acceptance derivation (Sections 6.1, 6.6, 7) | `analysis/extra_stats.py` | `results/extra_stats.json` |
| Tables 9 and 10 (codec, latency), Supplementary Fig. S1 and Table S3 (latency distribution, suites and junk) | Go measurement tests (steps 5, 8, 9) | `primitives.json`, `handshake_inprocess.json`, `conn_latency_*.json`, `junk_cost.json` |
| Figure 9 (six-bit test) | `analysis/stats.py` | `results/six_go.npy`, `six_rust.npy` |
| Table 11 and Supplementary Section S6 (Drivel) | `drivel/kemeleon-eval/main.go`, `analysis/drivel_eval.py` | `results/drivel.json` |
| Supplementary Table S2 (GFW rules) | `analysis/stats.py` | `results/stats.json` |
| Supplementary Table S4 (NIST SP 800-22) | `analysis/nist.py` | `results/nist.json` |