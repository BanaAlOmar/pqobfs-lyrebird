# AVX2 ML-KEM and Keccak-x4 assembly returns without VZEROUPPER (AVX-SSE transition penalty)

**Affected:** every release from v1.5.0 to v1.6.5 (latest checked): `pke/kyber/internal/common/amd64.s` (9 functions) and `simd/keccakf1600/f1600x4_amd64.s` contain YMM instructions but no `VZEROUPPER` before `RET`.

## Summary

Leaving the upper halves of the YMM registers dirty on return makes subsequent legacy-SSE code pay the AVX-SSE transition penalty. Go's SHA-256 (SHA-NI) uses legacy-SSE encodings, so any program that hashes after an ML-KEM operation is affected — e.g. a handshake that HMACs its transcript after decapsulating.

## Measurement

Go 1.24.7, CIRCL v1.5.0, Linux VM (2 vCPU Intel Xeon @ 2.1 GHz, SHA-NI). HMAC-SHA256 over 4 KiB, median of 2,000:

| condition | time |
|---|---|
| baseline | ~3–4 µs |
| immediately after `mlkem768.PrivateKey.DecapsulateTo` | ~280 µs |
| after `DecapsulateTo` + `VZEROUPPER` | ~3.6 µs |

In our pq-obfs handshake (lyrebird) this was most of the bridge's CPU time per handshake. The magnitude depends on the microarchitecture and, on VMs, on how the hypervisor manages XSAVE state; on some hosts it may be much smaller, but the fix costs nothing.

## Suggested fix

Emit `VZEROUPPER` before every `RET` in the AVX2 code paths (in the avo generators: `VZEROUPPER()` before `RET()`), as Go's own AVX2 assembly does. Workaround used downstream: a two-instruction assembly helper that executes `VZEROUPPER`, called after each CIRCL ML-KEM call.

Reproduction test: `internal/mlkem_kemeleon/avx_measure_test.go` in the pq-obfs lyrebird branch (`go test -tags measure -run TestMeasureAVXTransition -v`).
