#!/usr/bin/env python3
"""kemeleon-conformance: test the output distribution of an ML-KEM encoder.

Round-trip and interoperability tests cannot tell whether an obfuscating
encoder's output is uniform. This tool runs the wire-image tests of the
paper on a sample of an encoder's output and fails if any of them separates
the sample from uniform bytes -- or, with --expect raw, checks that a sample
of raw FIPS 203 objects is detected (a self-test of the tool).

Input: a binary file of concatenated fixed-size records, or a text file
with one hex record per line (--hex).

  kemeleon_conformance.py --kind ct --params 768 --encoding rejection out.bin
  kemeleon_conformance.py --kind ek --params 1024 --encoding default --hex keys.txt

Tests (alpha = 1e-3 unless --alpha):
  unused-bits   rejection encoding: the unused high-order accumulator bits
                are uniform (chi-square over 2^u values) and not stuck at 0
  range         12-bit fields >= q never occur in raw keys; flags samples
                where the fraction of out-of-range fields is too low
  msb           top-bit fraction of 12-bit fields (raw keys: 0.385)
  matched       matched filter on the Compress_du symbol preimage counts
  byte-chi2     byte histogram of the whole sample
  zero-run      no fixed byte positions (per-position chi-square, max)
Requires numpy and scipy. Exit status 0 = all tests pass, 1 = a test fails.
"""
import argparse, math, sys
import numpy as np
from scipy import stats as st

Q, N = 3329, 256
PARAMS = {512: (2, 10, 4), 768: (3, 10, 4), 1024: (4, 11, 5)}


def compress(x, d):
    return ((x.astype(np.int64) << d) * 2 + Q) // (2 * Q) & ((1 << d) - 1)


def sizes(params, kind, encoding):
    k, du, dv = PARAMS[params]
    if kind == "ek":
        raw = 384 * k + 32
        if encoding == "raw":
            return raw
        if encoding == "default":
            return 384 * k + 32
        b = (Q ** (k * N)).bit_length()
        return (b + 7) // 8 + 32
    raw = (k * N * du + N * dv) // 8
    if encoding == "raw":
        return raw
    if encoding == "default":
        return 384 * (k + 1)
    b = (Q ** (k * N)).bit_length()
    return (b + 7) // 8 + N * dv // 8


def unpack(b, d, n):
    """(m, nbytes) -> (m, n) little-endian d-bit fields."""
    bits = np.unpackbits(b, axis=1, bitorder="little")[:, : n * d]
    w = (1 << np.arange(d)).astype(np.int64)
    return bits.reshape(b.shape[0], n, d) @ w


def load(path, rec, hexmode):
    if hexmode:
        rows = [bytes.fromhex(l.strip()) for l in open(path) if l.strip()]
        if any(len(r) != rec for r in rows):
            sys.exit(f"records must be {rec} bytes")
        return np.frombuffer(b"".join(rows), np.uint8).reshape(-1, rec)
    a = np.fromfile(path, np.uint8)
    if a.size % rec:
        sys.exit(f"file size {a.size} is not a multiple of the record size {rec}")
    return a.reshape(-1, rec)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--kind", choices=["ek", "ct"], required=True)
    ap.add_argument("--params", type=int, choices=[512, 768, 1024], default=768)
    ap.add_argument("--encoding", choices=["rejection", "default", "raw"], default="rejection")
    ap.add_argument("--expect", choices=["uniform", "raw"], default="uniform",
                    help="uniform: an encoder under test must pass; raw: the tool must detect raw objects")
    ap.add_argument("--hex", action="store_true")
    ap.add_argument("--alpha", type=float, default=1e-3)
    a = ap.parse_args()

    k, du, dv = PARAMS[a.params]
    rec = sizes(a.params, a.kind, a.encoding)
    x = load(a.file, rec, a.hex)
    m = len(x)
    alpha = a.alpha
    results = []  # (name, p_value or None, detail)

    # Byte histogram over the whole sample.
    h = np.bincount(x.ravel(), minlength=256)
    results.append(("byte-chi2", st.chisquare(h).pvalue, f"{x.size} bytes"))

    # Fixed positions: per-position byte chi-square, Bonferroni over positions.
    if m >= 256 * 5:
        ps = [st.chisquare(np.bincount(x[:, j], minlength=256)).pvalue for j in range(rec)]
        results.append(("zero-run", min(1.0, min(ps) * rec), "min per-position p, Bonferroni"))

    # 12-bit field tests on the first 384k bytes (key layout).
    if a.kind == "ek":
        f = unpack(x[:, : 384 * k], 12, k * N)
        n_fields = f.size
        out = int((f >= Q).sum())
        p_out = (4096 - Q) / 4096
        results.append(("range", st.binom.cdf(out, n_fields, p_out), f"{out}/{n_fields} fields >= q"))
        top = int((f >= 2048).sum())
        results.append(("msb", 2 * min(st.binom.cdf(top, n_fields, .5), st.binom.sf(top - 1, n_fields, .5)),
                        f"top-bit fraction {top / n_fields:.4f}"))

    # Matched filter on the Compress_du layout of c_1.
    if a.kind == "ct":
        c1b = k * N * du // 8
        sym = unpack(x[:, :c1b], du, k * N)
        counts = np.bincount(compress(np.arange(Q), du), minlength=1 << du)
        big = counts == counts.max()
        n_sym = sym.size
        kb = int(big[sym].sum())
        p_u = big.sum() / (1 << du)
        results.append(("matched", st.binom.sf(kb - 1, n_sym, p_u), f"{kb}/{n_sym} large-preimage symbols"))

    # Unused accumulator bits (rejection encoding).
    if a.encoding == "rejection":
        b = (Q ** (k * N)).bit_length()
        L = (b + 7) // 8
        shift = (b - 1) - 8 * (L - 1)
        u = 8 - shift
        v = x[:, L - 1] >> shift
        cnt = np.bincount(v, minlength=1 << u)
        results.append(("unused-bits", st.chisquare(cnt).pvalue if m >= 5 * (1 << u) else None,
                        f"{u} unused bits, {int((v == 0).sum())}/{m} all-zero (uniform: {m / (1 << u):.1f})"))
        results.append(("unused-bits-zero", st.binom.sf(int((v == 0).sum()) - 1, m, 2.0 ** -u), "excess of all-zero values"))

    fail = False
    print(f"{a.file}: {m} records of {rec} bytes ({a.kind}, ML-KEM-{a.params}, {a.encoding}), alpha={alpha:g}")
    for name, p, detail in results:
        if p is None:
            print(f"  {name:17s} skipped ({detail}; sample too small)")
            continue
        bad = p < alpha
        print(f"  {name:17s} p={p:.3g}  {'FAIL' if bad else 'pass'}  ({detail})")
        fail |= bad
    if a.expect == "raw":
        print("result:", "DETECTED (tool self-test ok)" if fail else "NOT DETECTED (self-test failed)")
        sys.exit(0 if fail else 1)
    print("result:", "FAIL: output distinguishable from uniform" if fail else "PASS")
    sys.exit(1 if fail else 0)


if __name__ == "__main__":
    main()
