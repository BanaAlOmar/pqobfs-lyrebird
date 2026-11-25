#!/usr/bin/env python3
"""Wire-image tests on Drivel's Kemeleon (non-rejection) ciphertext encodings.
Input: drivel_<param>.bin from cmd/kemeleon-eval (concatenated encodings).
Output: results/drivel.json"""
import json, math, os, sys
import numpy as np
from scipy import stats as st

D = os.environ.get("DRIVEL_DIR", "/tmp/drivel")
DFIX = os.environ.get("DRIVEL_FIX_DIR", "/tmp/drivel_fix")  # same harness, t set so that b+t = 8*len
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
q = 3329
P = {"ML-KEM-768": (3, 192, 1522), "ML-KEM-1024": (4, 256, 1905)}  # k, t, encoded length (bytes)


def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [c - h, c + h]


def evaluate(D, name, k, t, L):
    a = np.fromfile(f"{D}/drivel_{name}.bin", dtype=np.uint8).reshape(-1, L)
    n = len(a)
    l = (k + 1) * 256
    b = math.ceil(l * math.log2(q))
    unused = 8 * L - (b + t)  # top bits of the big-endian encoding that are never set
    top = a[:, 0]
    mask = (0xFF << (8 - unused)) & 0xFF if unused > 0 else 0
    zero_top = int(((top & mask) == 0).sum()) if unused > 0 else int(((top & 0xC0) == 0).sum())  # aligned: rate of top-2-zero, expect 1/4
    # Uniform bytes would have the top 'unused' bits all zero with probability 2^-unused.
    # Per-position chi-square over the first and a middle byte, and overall byte chi-square.
    def chi_pos(col):
        h = np.bincount(a[:, col], minlength=256); e = n / 256
        return float(st.chi2.sf(((h - e) ** 2 / e).sum(), 255))
    hall = np.bincount(a.ravel(), minlength=256); e = a.size / 256
    r = {
        "n": n, "encoded_bytes": L, "bits_b_plus_t": b + t, "unused_top_bits": unused,
        "top_bits_zero": zero_top, "top_bits_zero_rate_ci95": wilson(zero_top, n),
        "uniform_false_positive_rate": 2.0 ** -unused,
        "first_byte_max": int(top.max()),
        "p_first_byte": chi_pos(0), "p_middle_byte": chi_pos(L // 2), "p_last_byte": chi_pos(L - 1),
        "p_byte_chi2_all": float(st.chi2.sf(((hall - e) ** 2 / e).sum(), 255)),
        "first_byte_uniform_below_bound_p": float(st.chi2.sf(
            ((np.bincount(top, minlength=1 << (8 - unused))[: 1 << (8 - unused)] - n / (1 << (8 - unused))) ** 2
             / (n / (1 << (8 - unused)))).sum(), (1 << (8 - unused)) - 1)) if unused > 0 else None,
    }
    r["t"] = t
    r["censor_flags_rate"] = zero_top / n
    return r


res = {"as_shipped": {}, "byte_aligned_t": {}}
for name, (k, t, L) in P.items():
    res["as_shipped"][name] = evaluate(D, name, k, t, L)
    l = (k + 1) * 256; b = math.ceil(l * math.log2(q))
    if os.path.exists(f"{DFIX}/drivel_{name}.bin"):
        res["byte_aligned_t"][name] = evaluate(DFIX, name, k, 8 * L - b, L)
for v in res:
    for name in res[v]:
        print(v, name, json.dumps({x: res[v][name][x] for x in ("t", "unused_top_bits", "top_bits_zero", "first_byte_max", "p_first_byte", "p_byte_chi2_all")}))
json.dump(res, open(os.path.join(OUT, "drivel.json"), "w"), indent=1)


# Handshake length policy, derived from constants in transports/drivel/handshake.go
# (maxHandshakeLength = 53248; KdfOutLength = 32; mark = mac = 16; inline seed frame = 18 + 3 + 24 = 45)
# for kem = ML-KEM-768 and okem = ML-KEM-768 with Kemeleon (c_S = 1522 bytes). Padding is uniform.
MAXH, MARK, MAC, AUTH, SEEDF = 53248, 16, 16, 32, 45
epk, ect, cs = 1184, 1088, 1522
cmin = epk + cs + MARK + MAC
smin = ect + AUTH + MARK + MAC
cpad = (max(0, smin + SEEDF - cmin), MAXH - cmin)
spad = (0, MAXH - (smin + SEEDF))
OBFS4_MAX = 8192
c_lo, c_hi = cmin + cpad[0], cmin + cpad[1]
s_lo, s_hi = smin + SEEDF + spad[0], smin + SEEDF + spad[1]
res["length_policy_ML-KEM-768"] = {
    "client_first_flight_range": [c_lo, c_hi], "client_mean": (c_lo + c_hi) / 2,
    "server_first_flight_range": [s_lo, s_hi], "server_mean": (s_lo + s_hi) / 2,
    "p_client_above_obfs4_max": (c_hi - OBFS4_MAX) / (c_hi - c_lo + 1),
    "p_server_above_obfs4_max": (s_hi - OBFS4_MAX) / (s_hi - s_lo + 1),
    "obfs4_max_handshake": OBFS4_MAX,
}
print(json.dumps(res["length_policy_ML-KEM-768"]))
json.dump(res, open(os.path.join(OUT, "drivel.json"), "w"), indent=1)
