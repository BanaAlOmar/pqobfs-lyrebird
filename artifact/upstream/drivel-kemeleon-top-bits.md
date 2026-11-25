# Kemeleon ciphertext encoding leaves the top bits at zero (distinguisher)

**Affected:** `lyrebird-drivel` at commit `21c0d06`, `internal/cryptofactory/encoding_kemeleon/encoding_kemeleon.go`. ML-KEM-768 and ML-KEM-1024 measured; ML-KEM-512 follows from the same arithmetic.

## Summary

`vectorEncodeNR` follows the non-rejection `VectorEncode` of draft-irtf-cfrg-kemeleon: it accumulates the coefficients into r, samples m from [0, floor((2^(b+t) − r)/q^l)], and returns r + m·q^l, which is below 2^(b+t). `EncodeCiphertext` then writes the integer big-endian into `kemeleonCtxtLength` bytes with `FillBytes`.

This follows revisions -00 (April 2025) and -01 (January 2026) of the draft, where t is a security parameter and the whole ciphertext is encoded as one integer. Neither revision sizes the output to b + t, and here b + t is not a multiple of 8, so the integer is shorter than the byte string that carries it. Revision -02 (July 2026) encodes each polynomial separately and chooses t so that the output is byte-aligned, which removes the problem; implementations of -00/-01 inherit it. The values in use:

| Parameter set | l = (k+1)·256 | b = ⌈l·log2 q⌉ | t | b + t | Output bits | Fixed zero bits |
|---|---|---|---|---|---|---|
| ML-KEM-512 | 768 | 8987 | 128 | 9115 | 9120 (1140 B) | 5 |
| ML-KEM-768 | 1024 | 11982 | 192 | 12174 | 12176 (1522 B) | 2 |
| ML-KEM-1024 | 1280 | 14978 | 256 | 15234 | 15240 (1905 B) | 6 |

The top bits of the first byte of c_S are therefore always zero.

## Impact

c_S is the only Kemeleon-encoded field in the client's first flight (it follows the encrypted ephemeral key epk_e, whose length is fixed), so its first byte sits at a fixed offset. A censor that tests those bits flags every Drivel handshake. The false-positive rate on uniform traffic is 1/4 for ML-KEM-768, 1/32 for ML-KEM-512 and 1/64 for ML-KEM-1024. Combined with other weak features, this is a strong filter. Encode/decode round trips do not reveal the problem.

Measured with 10,000 encodings per parameter set (Go `crypto/mlkem` ciphertexts encoded by `KemeleonEncoder`; every round trip exact):

* ML-KEM-768: the top 2 bits were zero in 10,000/10,000 (the largest first byte was 63); a chi-square test of the first byte gives p < 10^-300.
* ML-KEM-1024: the top 6 bits were zero in 10,000/10,000 (the largest first byte was 3); chi-square over all bytes gives p = 8·10^-26.

## Suggested fix

Either move to the -02 encoding (a format change), or, keeping the current format, set t so that b + t equals the output length in bits: t = 133 (ML-KEM-512), 194 (ML-KEM-768), 262 (ML-KEM-1024), or compute `t = 8*kemeleonCtxtLength - b` in `vectorEncodeNR`. Each value is at least the current one, so the statistical distance from uniform only shrinks. `vectorDecodeNR` reduces modulo q^l and does not use t, so existing decoders accept the new encodings unchanged.

With this change (same harness, 10,000 encodings each), the top two bits were zero in 2,531/10,000 (ML-KEM-768) and 2,430/10,000 (ML-KEM-1024), matching the 1/4 expected for uniform bytes, and no byte-level test rejected at the Bonferroni-corrected 5% level. A unit test that checks the high bits of many encodings, like the one we use for pq-obfs, would catch regressions.

## Reproduction

`artifact/drivel/kemeleon-eval/main.go` (copy into `cmd/kemeleon-eval/` of the Drivel tree):

```
go run ./cmd/kemeleon-eval /tmp/drivel 10000
DRIVEL_DIR=/tmp/drivel python3 artifact/analysis/drivel_eval.py
```

Found by the conformance tests in the paper "Migrating a Deployed Censorship-Circumvention Transport to Post-Quantum Key Exchange" (under submission). Happy to send a PR.
