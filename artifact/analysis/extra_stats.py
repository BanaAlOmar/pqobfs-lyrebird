#!/usr/bin/env python3
"""Additional statistics requested in review.

1. Effect sizes for the payload tests on encoded objects (mean MSB count, mean K4)
   with 95% CIs, against their exact null expectations.
2. The six unused bits of byte 1,123 of encoded ML-KEM-768 ciphertexts: joint
   uniformity over 64 patterns, independence from the two accumulator bits in the same
   byte and from the top bits of byte 1,122, and serial independence between
   consecutive encodings (a counter or a reused value would fail).
3. Adoption share of the obfs4 padding floor: false-positive probability per obfs4
   connection and connections needed by the optimal length test, as a function of the
   share s of obfs4 clients that pad to the floor (the bridge-side floor applies to
   every connection).
4. Kemeleon ciphertext acceptance, derived and compared with the measurement.
Output: results/extra_stats.json
"""
import json, math, os
import numpy as np
from scipy import stats as st

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("RESULTS_DIR", os.path.join(HERE, "results"))
CORPUS = os.environ.get("CORPUS_DIR", "/tmp/corpus")
res = {}

# 1. effect sizes
pc = np.load(os.path.join(OUT, "popcount.npz"))
def mean_ci(x):
    x = np.asarray(x, float); m = x.mean(); h = 1.96 * x.std(ddof=1) / math.sqrt(len(x)); return [float(m), float(m - h), float(m + h)]
res["effect"] = {"msb_enc": mean_ci(pc["msb_enc"]), "msb_null": 384.0, "msb_raw": mean_ci(pc["msb_raw"]),
                 "k4_enc": mean_ci(pc["k4_enc"]), "k4_null": 768 * 257 / 1024, "k4_raw": mean_ci(pc["k4_raw"]),
                 "msb_fraction_enc": [v / 768 for v in mean_ci(pc["msb_enc"])]}

# 2. six unused bits
six = {}
for impl in ("circl", "gostd"):
    a = np.fromfile(f"{CORPUS}/ct_enc_{impl}.bin", dtype=np.uint8).reshape(-1, 1252)
    b1123, b1122 = a[:, 1123], a[:, 1122]
    pat = b1123 >> 2; acc2 = b1123 & 3; top1122 = b1122 >> 6
    n = len(a)
    h = np.bincount(pat, minlength=64); e = n / 64
    joint_p = float(st.chi2.sf(((h - e) ** 2 / e).sum(), 63))
    def indep(x, y, kx, ky):
        t = np.zeros((kx, ky)); np.add.at(t, (x, y), 1)
        return float(st.chi2_contingency(t)[1])
    # serial: consecutive encodings, lag-1 autocorrelation of the pattern and chi-square on (pattern mod 8) pairs
    r = float(np.corrcoef(pat[:-1], pat[1:])[0, 1])
    pairs_p = indep((pat[:-1] & 7), (pat[1:] & 7), 8, 8)
    six[impl] = {"n": n, "joint_uniform_p": joint_p, "indep_acc_bits_p": indep(pat, acc2, 64, 4),
                 "indep_byte1122_top2_p": indep(pat, top1122, 64, 4), "lag1_corr": r,
                 "lag1_corr_p": float(2 * st.norm.sf(abs(r) * math.sqrt(n))), "lag1_pairs_p": pairs_p}
res["six_bits"] = six

# 3. adoption share
lo, hi = 141, 8192                     # obfs4 first-flight law, both directions
C, S = 2440, 1361                      # pq-obfs uniform minima (client, bridge incl. seed frame)
pc_ = (hi - C + 1) / (hi - lo + 1)     # P(old obfs4 client flight >= C)
ps_ = (hi - S + 1) / (hi - lo + 1)
shares = [0, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99]
def need(p, fpr):
    return math.inf if p >= 1 else math.ceil(math.log(fpr) / math.log(p))
res["adoption"] = {"p_client_old": pc_, "p_bridge_old": ps_, "p_no_floor": pc_ * ps_,
                   "n_no_floor": [need(pc_ * ps_, 1e-2), need(pc_ * ps_, 1e-3)], "by_share": {}}
for s in shares:
    p = s + (1 - s) * pc_              # bridge floor on: bridge direction always passes
    res["adoption"]["by_share"][str(s)] = {"p": p, "n_1e-2": need(p, 1e-2), "n_1e-3": need(p, 1e-3), "fpr_k20": p ** 20}

# 4. acceptance
q = 3329
L2 = 768 * math.log2(q)
acc_key = 2.0 ** (math.floor(L2) - L2)          # 2^floor(log2 q^768) / q^768
acc_c2 = (1 - 1 / q) ** 256            # each zero c2 coefficient (prob 209/3329) rejected w.p. 1/209
res["acceptance"] = {"key": acc_key, "c2_factor": acc_c2, "ct_derived": acc_key * acc_c2}
print(json.dumps(res, indent=1, default=str)[:3000])
def clean(o):
    if isinstance(o, dict): return {k: clean(v) for k, v in o.items()}
    if isinstance(o, list): return [clean(v) for v in o]
    return None if o == math.inf else o
json.dump(clean(res), open(os.path.join(OUT, "extra_stats.json"), "w"), indent=1)
