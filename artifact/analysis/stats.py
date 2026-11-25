#!/usr/bin/env python3
"""Statistical evaluation of the ML-KEM wire-image distinguishers.

Reads the corpora written by internal/mlkem_kemeleon/corpus_test.go and the
Rust reference vectors, and writes results/stats.json plus figures.

Exact nulls. Every statistic used here reduces to a binomial count:
  * range test:   K_range = #{12-bit fields >= q}; uniform: Bin(768, 767/4096),
                  raw FIPS 203 keys: identically 0.
  * MSB test:     K_msb   = #{12-bit fields with top bit set}; uniform:
                  Bin(768, 1/2), raw: Bin(768, 1281/3329).
  * matched filter on c_1: T = a*K4 + b*(768-K4) is increasing in
                  K4 = #{10-bit symbols with four preimages}; uniform:
                  Bin(768, 257/1024), raw: Bin(768, 1028/3329).
so thresholds, detection rates and ROC curves are computed exactly rather
than from a finite reference corpus. Empirical rates on the corpora are
reported alongside, with Wilson 95% intervals.
"""
import json, math, os, sys
import numpy as np
from scipy import stats as st

Q = 3329
CORPUS = os.environ.get("CORPUS_DIR", "/tmp/corpus")
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
os.makedirs(OUT, exist_ok=True)
ALPHA = 1e-3
rng = np.random.default_rng(20261120)

def load(name, rec):
    b = np.fromfile(os.path.join(CORPUS, name), dtype=np.uint8)
    return b.reshape(-1, rec)

def wilson(k, n, z=1.959964):
    if n == 0:
        return (float("nan"),) * 3
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)

def unpack12(b):
    """(N, 1152) bytes -> (N, 768) 12-bit little-endian fields (FIPS 203)."""
    b = b[:, :1152].astype(np.uint16).reshape(-1, 384, 3)
    lo = b[:, :, 0] | ((b[:, :, 1] & 0x0F) << 8)
    hi = (b[:, :, 1] >> 4) | (b[:, :, 2] << 4)
    return np.stack([lo, hi], axis=2).reshape(-1, 768)

def unpack10(b):
    """(N, 960) bytes -> (N, 768) 10-bit little-endian symbols."""
    b = b[:, :960].astype(np.uint32).reshape(-1, 192, 5)
    w = (b[:, :, 0] | (b[:, :, 1] << 8) | (b[:, :, 2] << 16) | (b[:, :, 3] << 24)
         | (b[:, :, 4].astype(np.uint64) << 32).astype(np.uint64))
    w = w.astype(np.uint64)
    out = np.stack([(w >> (10 * i)) & 0x3FF for i in range(4)], axis=2)
    return out.reshape(-1, 768).astype(np.uint16)

def compress10(x):
    return ((x.astype(np.uint64) * 2048 + Q) // (2 * Q)) & 0x3FF

# Four-preimage symbols of Compress_10 (exhaustive over Z_q).
counts = np.bincount(compress10(np.arange(Q)), minlength=1024)
FOUR = counts == 4
assert FOUR.sum() == 257 and (counts == 3).sum() == 767

P_RANGE_U = 767 / 4096
P_MSB_U, P_MSB_RAW = 0.5, 1281 / Q
P4_U, P4_RAW = 257 / 1024, 1028 / Q

# --------------------------------------------------------------- statistics
def k_range(eks):  return (unpack12(eks) >= Q).sum(1)
def k_msb(eks):    return (unpack12(eks) >= 2048).sum(1)
def k_four(cts):   return FOUR[unpack10(cts)].sum(1)

def chi2_bytes(x):
    n = x.shape[1]
    e = n / 256
    h = np.stack([np.bincount(r, minlength=256) for r in x])
    return ((h - e) ** 2 / e).sum(1)

CHI2_CRIT = st.chi2.ppf(1 - ALPHA, 255)

# MSB: two-sided at alpha on Bin(768, 1/2), exact.
def msb_bounds(n=768, alpha=ALPHA):
    lo = st.binom.ppf(alpha / 2, n, 0.5)
    hi = st.binom.isf(alpha / 2, n, 0.5)
    # reject if k < lo or k > hi
    return int(lo), int(hi)
MSB_LO, MSB_HI = msb_bounds()

# Matched filter: one-sided upper test on K4 at alpha, exact.
def k4_crit(n=768, alpha=ALPHA):
    k = int(st.binom.isf(alpha, n, P4_U))
    while st.binom.sf(k - 1, n, P4_U) > alpha:
        k += 1
    return k  # reject if K4 >= k
K4_CRIT = k4_crit()

def a_b():
    return math.log(4096 / Q), math.log(3072 / Q)

res = {"alpha": ALPHA}

# Analytic summary.
a, b = a_b()
dkl = (1028 / Q) * a + (1 - 1028 / Q) * b  # per-coefficient KL(raw || uniform) in nats
res["analytic"] = {
    "range_uniform_pass_prob": (1 - P_RANGE_U) ** 768,
    "range_uniform_pass_log10": 768 * math.log10(1 - P_RANGE_U),
    "msb_bounds": [MSB_LO, MSB_HI],
    "msb_mean_uniform": 384, "msb_mean_raw": 768 * P_MSB_RAW,
    "msb_sd_uniform": math.sqrt(768 * .25), "msb_sd_raw": math.sqrt(768 * P_MSB_RAW * (1 - P_MSB_RAW)),
    "msb_sep_sigma": (384 - 768 * P_MSB_RAW) / math.sqrt(768 * .25),
    "msb_detect_exact": float(st.binom.cdf(MSB_LO - 1, 768, P_MSB_RAW) + st.binom.sf(MSB_HI, 768, P_MSB_RAW)),
    "msb_fpr_exact": float(st.binom.cdf(MSB_LO - 1, 768, .5) + st.binom.sf(MSB_HI, 768, .5)),
    "mf_kl_nats_per_coeff": dkl,
    "mf_k4_crit": K4_CRIT,
    "mf_fpr_exact": float(st.binom.sf(K4_CRIT - 1, 768, P4_U)),
    "mf_detect_exact_1ct": float(st.binom.sf(K4_CRIT - 1, 768, P4_RAW)),
    "mf_mean_score_raw": 768 * ((1028 / Q) * a + (1 - 1028 / Q) * b),
    "mf_mean_score_uniform": 768 * ((257 / 1024) * a + (767 / 1024) * b),
    "mf_sep_sigma": (768 * (P4_RAW - P4_U)) / math.sqrt(768 * P4_U * (1 - P4_U)),
    "chi2_crit": float(CHI2_CRIT),
}

# Multi-ciphertext / multi-connection matched filter (two raw CTs per connection).
mc = {}
for m in [1, 2, 4, 6, 10]:
    n = 768 * m
    kc = k4_crit(n)
    mc[m] = float(st.binom.sf(kc - 1, n, P4_RAW))
res["analytic"]["mf_detect_vs_ciphertexts"] = mc

# ------------------------------------------------------------ empirical keys
def rate(mask):
    k, n = int(mask.sum()), int(mask.size)
    p, lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": p, "ci95": [lo, hi]}

U_EK = rng.integers(0, 256, size=(100000, 1156), dtype=np.uint8)  # uniform reference
keys = {}
for gen in ["kyberpy", "gostd", "circl"]:
    raw = load(f"ek_raw_{gen}.bin", 1184)
    enc = load(f"ek_enc_{gen}.bin", 1156)
    d = {}
    for lbl, x in [("raw", raw), ("encoded", enc)]:
        kr, km = k_range(x), k_msb(x)
        c2 = chi2_bytes(x)
        d[lbl] = {
            "range_test": rate(kr == 0),
            "msb_test": rate((km < MSB_LO) | (km > MSB_HI)),
            "chi2_test": rate(c2 > CHI2_CRIT),
            "msb_mean": float(km.mean()), "msb_sd": float(km.std()),
            "msb_fraction": float(km.mean() / 768),
            "popcount_per_byte": float(np.unpackbits(x, axis=1).sum(1).mean() / x.shape[1]),
        }
    keys[gen] = d
kr_u = k_range(U_EK)
km_u = k_msb(U_EK)
keys["uniform_reference"] = {
    "range_test": rate(kr_u == 0),
    "msb_test": rate((km_u < MSB_LO) | (km_u > MSB_HI)),
    "chi2_test": rate(chi2_bytes(U_EK[:20000]) > CHI2_CRIT),
}
res["keys"] = keys

# ----------------------------------------------------- empirical ciphertexts
U_CT = rng.integers(0, 256, size=(1000000, 960), dtype=np.uint8)
k4_u = np.concatenate([k_four(U_CT[i:i + 100000]) for i in range(0, len(U_CT), 100000)])
cts = {"uniform_reference_1e6": rate(k4_u >= K4_CRIT)}
score = lambda k: a * k + b * (768 - k)
for gen in ["gostd", "circl"]:
    raw = load(f"ct_raw_{gen}.bin", 1088)
    enc = load(f"ct_enc_{gen}.bin", 1252)
    d = {}
    for lbl, x in [("raw", raw), ("encoded", enc)]:
        k4 = k_four(x)
        s = score(k4)
        d[lbl] = {"matched_filter": rate(k4 >= K4_CRIT),
                  "mean_score": float(s.mean()), "sd_score": float(s.std()),
                  "sep_sigma": float((s.mean() - score(768 * P4_U)) / (math.sqrt(768 * P4_U * (1 - P4_U)) * (a - b)))}
    # Two ciphertexts per connection: pair consecutive raw CTs.
    k4r = k_four(raw)
    pair = k4r[: len(k4r) // 2 * 2].reshape(-1, 2).sum(1)
    d["raw_two_per_connection"] = rate(pair >= k4_crit(1536))
    cts[gen] = d
res["ciphertexts"] = cts

# ------------------------------------------------- reference encoder (Rust)
rust = [json.loads(l) for l in open(os.path.join(CORPUS, "rust_vectors.json"))]
r_ct = np.array([np.frombuffer(bytes.fromhex(v["ct_kmln"]), np.uint8) for v in rust])
r_ek = np.array([np.frombuffer(bytes.fromhex(v["ek_kmln"]), np.uint8) for v in rust])
go_ct = load("ct_enc_circl.bin", 1252)
go_ek = load("ek_enc_circl.bin", 1156)
def six(x): return (x[:, 1123] & 0xFC) >> 2
six_res = {}
for lbl, x in [("rust_ct", r_ct), ("rust_ek", r_ek), ("go_ct", go_ct), ("go_ek", go_ek)]:
    v = six(x)
    six_res[lbl] = {"n": int(len(v)), "zero": rate(v == 0),
                    "distinct_values": int(len(np.unique(v))),
                    "chi2_64_p": float(st.chisquare(np.bincount(v, minlength=64)).pvalue)}
six_res["fpr_one_message"] = 1 / 64
six_res["fpr_two_messages"] = 1 / 4096
res["six_bit"] = six_res
np.save(os.path.join(OUT, "six_rust.npy"), six(r_ct))
np.save(os.path.join(OUT, "six_go.npy"), six(go_ct[:1000]))

# --------------------------------------------------------------- GFW rules
def printable(x): return (x >= 0x20) & (x <= 0x7E)
def gfw_flag(p):
    """Wu et al. (USENIX Security 2023) fully-encrypted-traffic rules applied
    to a client's first TCP payload. Returns True when the payload is NOT
    exempted, i.e. treated as fully encrypted."""
    pc = np.unpackbits(p, axis=1).sum(1) / p.shape[1]
    ex1 = (pc <= 3.4) | (pc >= 4.6)
    pr = printable(p)
    ex2 = pr[:, :6].all(1)
    ex3 = pr.mean(1) > 0.5
    # Ex4: more than 20 contiguous printable bytes.
    run = np.zeros(len(p), int); best = np.zeros(len(p), int)
    for j in range(p.shape[1]):
        run = np.where(pr[:, j], run + 1, 0); best = np.maximum(best, run)
    ex4 = best > 20
    tls = (p[:, 0] == 0x16) & (p[:, 1] == 0x03) & (p[:, 2] <= 0x03)
    http = np.zeros(len(p), bool)
    for m in [b"GET ", b"PUT ", b"POST", b"HEAD"]:
        http |= (p[:, :4] == np.frombuffer(m, np.uint8)).all(1)
    ex5 = tls | http
    exempt = ex1 | ex2 | ex3 | ex4 | ex5
    return ~exempt, {"ex1": float(ex1.mean()), "ex2": float(ex2.mean()), "ex3": float(ex3.mean()),
                     "ex4": float(ex4.mean()), "ex5": float(ex5.mean())}

SEG = 1448
n = 10000
ct_raw = load("ct_raw_circl.bin", 1088)[:n]; ek_raw = load("ek_raw_circl.bin", 1184)[:n]
ct_enc = load("ct_enc_circl.bin", 1252)[:n]; ek_enc = load("ek_enc_circl.bin", 1156)[:n]
first = {
    "obfs4 (uniform bytes)": rng.integers(0, 256, size=(n, SEG), dtype=np.uint8),
    "pq-obfs, raw ML-KEM": np.concatenate([ct_raw, ek_raw], 1)[:, :SEG],
    "pq-obfs, Kemeleon": np.concatenate([ct_enc, ek_enc], 1)[:, :SEG],
}
g = {}
for k, x in first.items():
    flag, parts = gfw_flag(x)
    g[k] = {"flagged_as_fully_encrypted": rate(flag), "exemption_rates": parts,
            "popcount_per_byte": float(np.unpackbits(x, axis=1).sum(1).mean() / SEG)}
res["gfw_rules"] = g

# --------------------------------------------------------------- ROC (exact)
def roc_binom(n, p0, p1, upper=True):
    ks = np.arange(n + 1)
    if upper:  # reject for large k
        fpr = st.binom.sf(ks - 1, n, p0); tpr = st.binom.sf(ks - 1, n, p1)
    else:
        fpr = st.binom.cdf(ks, n, p0); tpr = st.binom.cdf(ks, n, p1)
    return fpr, tpr
roc = {}
f, t = roc_binom(768, .5, P_MSB_RAW, upper=False); roc["msb"] = (f, t)
f, t = roc_binom(768, P4_U, P4_RAW, upper=True); roc["mf_1ct"] = (f, t)
f, t = roc_binom(1536, P4_U, P4_RAW, upper=True); roc["mf_2ct"] = (f, t)
def auc(f, t):
    o = np.argsort(f); return float(np.trapezoid(np.r_[0, t[o], 1], np.r_[0, f[o], 1]))
res["auc"] = {k: auc(*v) for k, v in roc.items()}
res["auc"]["range"] = 1.0
# Empirical ROC of the matched filter on encoded vs uniform.
k4e = k_four(load("ct_enc_circl.bin", 1252))
res["auc"]["mf_encoded_vs_uniform_empirical"] = float(
    st.mannwhitneyu(k4e, k4_u[:len(k4e) * 10]).statistic / (len(k4e) * len(k4e) * 10))
np.savez(os.path.join(OUT, "roc.npz"), **{k + "_f": v[0] for k, v in roc.items()},
         **{k + "_t": v[1] for k, v in roc.items()})

# Popcount histograms for the figure.
np.savez(os.path.join(OUT, "popcount.npz"),
         raw=np.unpackbits(load("ek_raw_circl.bin", 1184)[:1000], axis=1).reshape(1000, -1, 8).sum(2).mean(1),
         enc=np.unpackbits(load("ek_enc_circl.bin", 1156)[:1000], axis=1).reshape(1000, -1, 8).sum(2).mean(1),
         msb_raw=k_msb(load("ek_raw_circl.bin", 1184)), msb_enc=k_msb(load("ek_enc_circl.bin", 1156)),
         k4_raw=k_four(load("ct_raw_circl.bin", 1088)), k4_enc=k4e)

acc = json.load(open(os.path.join(CORPUS, "acceptance.json")))
res["acceptance"] = {k: {"accepted": v[0], "trials": v[1], "rate": wilson(v[0], v[1])[0],
                         "ci95": list(wilson(v[0], v[1])[1:])} for k, v in acc.items()}
res["acceptance"]["ek_exact_spec"] = None  # filled below
# Exact EK acceptance: P(top 6 bits of byte 1123 are 0 | r uniform in [0, q^768)).
qn = Q ** 768
res["acceptance"]["ek_exact_spec"] = float(min(qn, 2 ** 8986) / qn)

json.dump(res, open(os.path.join(OUT, "stats.json"), "w"), indent=1, default=float)
print(json.dumps(res, indent=1, default=float)[:6000])
