#!/usr/bin/env python3
"""Generic rejection-sampling Kemeleon encoder for ML-KEM-512/768/1024 and the
wire-image analysis of all three parameter sets.

The encoder follows the same steps as the Go implementation (which covers
ML-KEM-768 only): accumulate r = sum t_i q^i over the k*n coefficients,
reject if r >= 2^(b-1) with b = bitlen(q^(kn)), fill the unused high-order
bits of the last byte with random bits; for ciphertexts first replace every
c_1 symbol by a uniform preimage under Compress_du and reject zero-valued c_2
symbols with probability 1/ceil(q / 2^dv). Its ML-KEM-768 output is
cross-checked against the Go decoder (see check_against_go()).
"""
import json, math, os, secrets, sys
import numpy as np
from scipy import stats as st
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

Q, N = 3329, 256
PARAMS = {"ML-KEM-512": (2, 10, 4, ML_KEM_512), "ML-KEM-768": (3, 10, 4, ML_KEM_768),
          "ML-KEM-1024": (4, 11, 5, ML_KEM_1024)}
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))

def compress(x, d): return ((x << d) * 2 + Q) // (2 * Q) & ((1 << d) - 1)
def decompress(y, d): return (y * Q * 2 + (1 << d)) // (2 << d)

_pre = {}
def preimages(d):
    if d not in _pre:
        p = [[] for _ in range(1 << d)]
        for x in range(Q):
            p[compress(x, d)].append(x)
        _pre[d] = p
    return _pre[d]

def unpack(b, d, n):
    v = int.from_bytes(b, "little")
    m = (1 << d) - 1
    return [(v >> (d * i)) & m for i in range(n)]

def layout(k):
    b = (Q ** (k * N)).bit_length()
    L = (b + 7) // 8
    data_bits_top = (b - 1) - 8 * (L - 1)     # index of bit b-1 within the top byte
    mask = (0xFF << data_bits_top) & 0xFF       # bits at and above b-1: rejected, then randomized
    return b, L, mask

def accumulate(coeffs, k):
    r = 0
    for c in reversed(coeffs):
        r = r * Q + c
    b, L, mask = layout(k)
    rb = bytearray(r.to_bytes(L, "little"))
    if rb[-1] & mask:
        return None
    rb[-1] |= secrets.randbits(8) & mask
    return bytes(rb)

def encode_ek(ek, k):
    t = unpack(ek[: 384 * k], 12, k * N)
    acc = accumulate(t, k)
    return None if acc is None else acc + ek[384 * k:]

def encode_ct(ct, k, du, dv):
    c1b = k * N * du // 8
    c1 = unpack(ct[:c1b], du, k * N)
    pre = preimages(du)
    t = [secrets.choice(pre[v]) for v in c1]
    acc = accumulate(t, k)
    if acc is None:
        return None
    c2 = unpack(ct[c1b:], dv, N)
    denom = -(-Q // (1 << dv))
    for v in c2:
        if v == 0 and secrets.randbelow(denom) == 0:
            return None
    return acc + ct[c1b:]

def analyse(name, n_obj):
    k, du, dv, kem = PARAMS[name]
    b, L, mask = layout(k)
    raw_ek, raw_ct, enc_ek, enc_ct = [], [], [], []
    ek_tr = ek_acc = ct_tr = ct_acc = 0
    while len(enc_ek) < n_obj or len(enc_ct) < n_obj:
        ek, dk = kem.keygen()
        if len(raw_ek) < n_obj:
            raw_ek.append(ek)
        ek_tr += 1
        e = encode_ek(ek, k)
        if e is not None:
            ek_acc += 1
            if len(enc_ek) < n_obj:
                enc_ek.append(e)
        K, ct = kem.encaps(ek)
        if len(raw_ct) < n_obj:
            raw_ct.append(ct)
        ct_tr += 1
        c = encode_ct(ct, k, du, dv)
        if c is not None:
            ct_acc += 1
            if len(enc_ct) < n_obj:
                enc_ct.append(c)

    kn = k * N
    p_range = (4096 - Q) / 4096
    # Matched filter on c_1 for Compress_du: count symbols with the larger
    # preimage set.
    sizes = np.array([len(s) for s in preimages(du)])
    big = sizes == sizes.max()
    p_big_u = big.sum() / (1 << du)
    p_big_raw = sizes[big].sum() / Q
    def kbig(cts):
        c1b = kn * du // 8
        return np.array([big[unpack(c[:c1b], du, kn)].sum() for c in cts])
    def crit(n, p0, alpha=1e-3):
        kc = int(st.binom.isf(alpha, n, p0))
        while st.binom.sf(kc - 1, n, p0) > alpha:
            kc += 1
        return kc
    kc = crit(kn, p_big_u)
    kc2 = crit(2 * kn, p_big_u)
    def fields(eks):
        return np.array([unpack(e[: 384 * k], 12, kn) for e in eks])
    fr, fe = fields(raw_ek), fields(enc_ek)
    lo = int(st.binom.ppf(5e-4, kn, .5)); hi = int(st.binom.isf(5e-4, kn, .5))
    msb = lambda f: (f >= 2048).sum(1)
    kr_raw, kr_enc = kbig(raw_ct), kbig(enc_ct)
    dkl = p_big_raw * math.log(p_big_raw / p_big_u) + (1 - p_big_raw) * math.log((1 - p_big_raw) / (1 - p_big_u))
    res = {
        "k": k, "du": du, "dv": dv,
        "raw_ek_bytes": len(raw_ek[0]), "raw_ct_bytes": len(raw_ct[0]),
        "enc_ek_bytes": len(enc_ek[0]), "enc_ct_bytes": len(enc_ct[0]),
        "accumulator_bytes": L, "unused_bits_mask": f"0x{mask:02X}",
        "ek_accept": ek_acc / ek_tr, "ek_accept_exact": 2 ** (b - 1) / Q ** kn,
        "ct_accept": ct_acc / ct_tr, "trials": [ek_tr, ct_tr],
        "client_min_bytes": len(enc_ct[0]) + len(enc_ek[0]) + 32,
        "server_min_bytes": len(enc_ct[0]) + 32 + 32,
        "range_detect_raw": float((((fr >= Q).sum(1)) == 0).mean()),
        "range_detect_enc": float((((fe >= Q).sum(1)) == 0).mean()),
        "range_fpr_log10": kn * math.log10(1 - p_range),
        "msb_detect_raw": float(((msb(fr) < lo) | (msb(fr) > hi)).mean()),
        "msb_detect_enc": float(((msb(fe) < lo) | (msb(fe) > hi)).mean()),
        "mf_symbols_with_more_preimages": int(big.sum()),
        "mf_kl_per_coeff": dkl,
        "mf_detect_raw_1ct": float((kr_raw >= kc).mean()),
        "mf_detect_raw_1ct_exact": float(st.binom.sf(kc - 1, kn, p_big_raw)),
        "mf_detect_raw_2ct_exact": float(st.binom.sf(kc2 - 1, 2 * kn, p_big_raw)),
        "mf_detect_enc_1ct": float((kr_enc >= kc).mean()),
        "unused_bits_zero_enc_ct": float(np.mean([(c[L - 1] & mask) == 0 for c in enc_ct])),
        "n": n_obj,
    }
    return res, enc_ct, enc_ek

def check_against_go(enc_ct, enc_ek):
    """Write ML-KEM-768 encodings for the Go cross-check test."""
    with open("/tmp/py768_vectors.bin", "wb") as f:
        for c, e in zip(enc_ct, enc_ek):
            f.write(c + e)

if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    out = {}
    for name in PARAMS:
        r, ct, ek = analyse(name, n)
        out[name] = r
        if name == "ML-KEM-768":
            check_against_go(ct, ek)
        print(name, json.dumps(r), flush=True)
    os.makedirs(OUT, exist_ok=True)
    json.dump(out, open(os.path.join(OUT, "paramsets.json"), "w"), indent=1)
