#!/usr/bin/env python3
"""Per-bridge censor with more simulated bridges and a permutation null.

The replicate-level analysis in defense_sim.py builds each simulated bridge from a
pool of 250 connections, so at large k the bridges overlap heavily and the AUC of a
single split varies widely. Here we pool the three replicates (1,500 connections per
configuration), split each class into disjoint train/test halves of 750, draw 2,000
bridges per class and split, each from k distinct connections, and repeat over 20
random splits. The permutation null shuffles the transport labels within the pooled
coordinated connections and runs the identical procedure: it shows the AUC spread to
expect when the two classes have the same distribution.
Output: results/defense_perbridge.json
"""
import json, os, sys
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("RESULTS_DIR", os.path.join(HERE, "results"))
DF = np.load(os.path.join(OUT, "defense_features.npz"))
KS = (1, 2, 5, 10, 20)
SPLITS = int(os.environ.get("PB_SPLITS", 20))
M = int(os.environ.get("PB_BRIDGES", 2000))
rng = np.random.default_rng(2026)


def bridges(F, k, m):
    """m bridges, each over k distinct connections drawn from pool F."""
    idx = np.argsort(rng.random((m, len(F))), axis=1)[:, :k]
    G = F[idx]
    return np.column_stack([G[:, :, 0].min(1), G[:, :, 1].min(1), G[:, :, 0].mean(1), G[:, :, 1].mean(1),
                            G[:, :, 2].min(1), G[:, :, 3].min(1),
                            G[:, :, 4].min(1), np.median(G[:, :, 4], 1), G[:, :, 4].mean(1)])


def one_split(A, B, k):
    pa, pb = rng.permutation(len(A)), rng.permutation(len(B))
    A1, A2 = A[pa[: len(A) // 2]], A[pa[len(A) // 2:]]
    B1, B2 = B[pb[: len(B) // 2]], B[pb[len(B) // 2:]]
    Xtr = np.vstack([bridges(A1, k, M), bridges(B1, k, M)])
    Xte = np.vstack([bridges(A2, k, M), bridges(B2, k, M)])
    y = np.r_[np.zeros(M), np.ones(M)]
    clf = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(Xtr, y)
    return float(roc_auc_score(y, clf.predict_proba(Xte)[:, 1]))


def summarize(v):
    v = np.array(v)
    return {"mean": float(v.mean()), "sd": float(v.std(ddof=1)),
            "lo95": float(np.percentile(v, 2.5)), "hi95": float(np.percentile(v, 97.5)), "values": v.tolist()}


COMPS = {"baseline": ("obfs4", "pq_uniform"), "light": ("obfs4_light", "pq_light"),
         "coordinated": ("obfs4_coord", "pq_coord")}
res = {"splits": SPLITS, "bridges_per_class": M, "connections_per_class": int(len(DF["obfs4"])), "comparisons": {}}
for name, (a, b) in COMPS.items():
    res["comparisons"][name] = {}
    for k in KS:
        res["comparisons"][name][str(k)] = summarize([one_split(DF[a], DF[b], k) for _ in range(SPLITS)])
        print(name, k, round(res["comparisons"][name][str(k)]["mean"], 3), round(res["comparisons"][name][str(k)]["sd"], 3), flush=True)
pool = np.vstack([DF["obfs4_coord"], DF["pq_coord"]])
n = len(DF["obfs4_coord"])
res["null_coordinated"] = {}
for k in KS:
    vals = []
    for _ in range(SPLITS):
        p = rng.permutation(len(pool))
        vals.append(one_split(pool[p[:n]], pool[p[n:]], k))
    res["null_coordinated"][str(k)] = summarize(vals)
    print("null", k, round(res["null_coordinated"][str(k)]["mean"], 3), round(res["null_coordinated"][str(k)]["sd"], 3), flush=True)
# Two-sided permutation-style comparison: is the coordinated split distribution shifted from the null?
from scipy.stats import mannwhitneyu
res["coordinated_vs_null_p"] = {str(k): float(mannwhitneyu(res["comparisons"]["coordinated"][str(k)]["values"],
                                                           res["null_coordinated"][str(k)]["values"]).pvalue) for k in KS}
print(res["coordinated_vs_null_p"])
# Which features carry any residual at k = 20 (coordinated)?
GROUPS = {"client_length": [0, 2], "bridge_length": [1, 3], "segments": [4, 5], "delay": [6, 7, 8]}


def one_split_cols(A, B, k, cols):
    pa, pb = rng.permutation(len(A)), rng.permutation(len(B))
    A1, A2 = A[pa[: len(A) // 2]], A[pa[len(A) // 2:]]
    B1, B2 = B[pb[: len(B) // 2]], B[pb[len(B) // 2:]]
    Xtr = np.vstack([bridges(A1, k, M), bridges(B1, k, M)])[:, cols]
    Xte = np.vstack([bridges(A2, k, M), bridges(B2, k, M)])[:, cols]
    y = np.r_[np.zeros(M), np.ones(M)]
    clf = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(Xtr, y)
    return float(roc_auc_score(y, clf.predict_proba(Xte)[:, 1]))


res["ablation_coordinated_k20"] = {g: summarize([one_split_cols(DF["obfs4_coord"], DF["pq_coord"], 20, c) for _ in range(10)])
                                   for g, c in GROUPS.items()}
print({g: round(v["mean"], 3) for g, v in res["ablation_coordinated_k20"].items()})
# Bridge flight length against the uniform law the code implements, per replicate (500 connections each).
lo, hi = 1361, 8192
res["bridge_length_mean"] = {"expected": (lo + hi) / 2, "se_per_replicate": float((hi - lo) / np.sqrt(12) / np.sqrt(500))}
for key in ("obfs4_coord", "pq_coord", "obfs4_light", "pq_light"):
    x = DF[key][:, 1]
    res["bridge_length_mean"][key] = [float(x[i * 500:(i + 1) * 500].mean()) for i in range(len(x) // 500)]
print(res["bridge_length_mean"])
json.dump(res, open(os.path.join(OUT, "defense_perbridge.json"), "w"), indent=1)
