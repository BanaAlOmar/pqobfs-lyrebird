#!/usr/bin/env python3
"""Statistical validation of the coordinated-cover results (reviewer requests).

Uses results/defense_features.npz (five replicates of 500 connections per
configuration, stacked in replicate order r1..r5).

1. Run holdout: classifiers are trained on replicates 1-3 and tested on 4-5, so no
   run contributes to both; also leave-one-replicate-out.
2. Stratified percentile bootstrap 95% and 90% CIs (1,000 resamples of the test connections of each class) and an equivalence test:
   the defense is declared equivalent to chance if the 90% CI of the AUC lies in
   [0.5 - DELTA, 0.5 + DELTA] (two one-sided tests at alpha = 0.05).
3. Four classifiers: gradient-boosted trees (as in the paper), logistic regression,
   random forest and k-nearest neighbours.
4. Per-bridge censor with the same run holdout: bridges for training are built from
   replicates 1-3, bridges for testing from replicates 4-5; permutation null.
Output: results/defense_stats.json
"""
import json, os
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("RESULTS_DIR", os.path.join(HERE, "results"))
DF = np.load(os.path.join(OUT, "defense_features.npz"))
NREP, PER = 5, 500
DELTA = float(os.environ.get("EQ_DELTA", 0.05))
B = 1000
rng = np.random.default_rng(7)

CLFS = {
    "gbt": lambda: HistGradientBoostingClassifier(max_iter=200, random_state=0),
    "logreg": lambda: make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
    "rf": lambda: RandomForestClassifier(n_estimators=500, min_samples_leaf=5, random_state=0, n_jobs=-1),
    "knn": lambda: make_pipeline(StandardScaler(), KNeighborsClassifier(n_neighbors=25)),
}
COMPS = {"baseline": ("obfs4", "pq_uniform"), "jitter500": ("obfs4", "pq_jitter500"),
         "jitter1000": ("obfs4", "pq_jitter1000"), "jitter2000": ("obfs4", "pq_jitter2000"),
         "light": ("obfs4_light", "pq_light"), "coordinated": ("obfs4_coord", "pq_coord"),
         "coord_vs_legacy": ("obfs4", "pq_coord")}
FEATS = {"lengths": [0, 1, 2, 3], "delay": [4], "both": [0, 1, 2, 3, 4]}


def reps(X, idx):
    return np.vstack([X[r * PER:(r + 1) * PER] for r in idx])


def boot_ci(y, s):
    """Percentile bootstrap, resampling the test connections of each class separately."""
    i0, i1 = np.flatnonzero(y == 0), np.flatnonzero(y == 1); v = []
    for _ in range(B):
        i = np.r_[rng.choice(i0, len(i0)), rng.choice(i1, len(i1))]
        v.append(roc_auc_score(y[i], s[i]))
    v = np.array(v)
    return [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))], [float(np.percentile(v, 5)), float(np.percentile(v, 95))]


def holdout(A, Bc, cols, clf, train=(0, 1, 2), test=(3, 4)):
    Xtr = np.vstack([reps(A, train), reps(Bc, train)])[:, cols]
    ytr = np.r_[np.zeros(len(train) * PER), np.ones(len(train) * PER)]
    Xte = np.vstack([reps(A, test), reps(Bc, test)])[:, cols]
    yte = np.r_[np.zeros(len(test) * PER), np.ones(len(test) * PER)]
    s = CLFS[clf]().fit(Xtr, ytr).predict_proba(Xte)[:, 1]
    return yte, s


res = {"delta": DELTA, "bootstrap": B, "classifiers": {
    "gbt": "HistGradientBoostingClassifier(max_iter=200, learning_rate=0.1, random_state=0)",
    "logreg": "StandardScaler + LogisticRegression(max_iter=2000)",
    "rf": "RandomForestClassifier(n_estimators=500, min_samples_leaf=5, random_state=0)",
    "knn": "StandardScaler + KNeighborsClassifier(n_neighbors=25)"},
    "holdout": {}, "lopo": {}, "per_replicate_cv": {}}

for name, (a, b) in COMPS.items():
    A, Bc = DF[a], DF[b]
    res["holdout"][name] = {}
    for clf in CLFS:
        res["holdout"][name][clf] = {}
        for fn, cols in FEATS.items():
            if clf != "gbt" and fn != "both":
                continue
            y, s = holdout(A, Bc, cols, clf)
            auc = float(roc_auc_score(y, s)); ci95, ci90 = boot_ci(y, s)
            res["holdout"][name][clf][fn] = {"auc": auc, "ci95": ci95, "ci90": ci90,
                                            "equivalent": bool(ci90[0] >= 0.5 - DELTA and ci90[1] <= 0.5 + DELTA)}
    # leave one replicate out, gbt, all features
    v = []
    for r in range(NREP):
        tr = tuple(i for i in range(NREP) if i != r)
        y, s = holdout(A, Bc, FEATS["both"], "gbt", tr, (r,))
        v.append(float(roc_auc_score(y, s)))
    res["lopo"][name] = {"per_replicate": v, "mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1))}
    print(name, {c: round(res["holdout"][name][c]["both"]["auc"], 3) for c in CLFS},
          res["holdout"][name]["gbt"]["both"]["ci95"], "LOPO", [round(x, 3) for x in v], flush=True)

# ---------------------------------------------------------- per-bridge holdout
M, KS, SPL = 2000, (1, 2, 5, 10, 20), 20


def bridges(F, k, m):
    idx = np.argsort(rng.random((m, len(F))), axis=1)[:, :k]
    G = F[idx]
    return np.column_stack([G[:, :, 0].min(1), G[:, :, 1].min(1), G[:, :, 0].mean(1), G[:, :, 1].mean(1),
                            G[:, :, 2].min(1), G[:, :, 3].min(1),
                            G[:, :, 4].min(1), np.median(G[:, :, 4], 1), G[:, :, 4].mean(1)])


def pb_holdout(Atr, Btr, Ate, Bte, k):
    Xtr = np.vstack([bridges(Atr, k, M), bridges(Btr, k, M)]); Xte = np.vstack([bridges(Ate, k, M), bridges(Bte, k, M)])
    y = np.r_[np.zeros(M), np.ones(M)]
    s = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(Xtr, y).predict_proba(Xte)[:, 1]
    return float(roc_auc_score(y, s))


def summ(v):
    v = np.array(v)
    return {"mean": float(v.mean()), "sd": float(v.std(ddof=1)), "lo95": float(np.percentile(v, 2.5)),
            "hi95": float(np.percentile(v, 97.5))}


res["per_bridge_holdout"] = {}
for name in ("baseline", "light", "coordinated"):
    a, b = COMPS[name]
    A, Bc = DF[a], DF[b]
    res["per_bridge_holdout"][name] = {str(k): summ([pb_holdout(reps(A, (0, 1, 2)), reps(Bc, (0, 1, 2)),
                                                                reps(A, (3, 4)), reps(Bc, (3, 4)), k) for _ in range(SPL)]) for k in KS}
    print("pb-holdout", name, {k: round(v["mean"], 3) for k, v in res["per_bridge_holdout"][name].items()}, flush=True)
# null: shuffle transport labels within training runs and within test runs separately
A, Bc = DF["obfs4_coord"], DF["pq_coord"]
tr = np.vstack([reps(A, (0, 1, 2)), reps(Bc, (0, 1, 2))]); te = np.vstack([reps(A, (3, 4)), reps(Bc, (3, 4))])
null = {}
for k in KS:
    v = []
    for _ in range(SPL):
        p, q = rng.permutation(len(tr)), rng.permutation(len(te))
        v.append(pb_holdout(tr[p[:len(tr) // 2]], tr[p[len(tr) // 2:]], te[q[:len(te) // 2]], te[q[len(te) // 2:]], k))
    null[str(k)] = summ(v)
res["per_bridge_holdout"]["null_coordinated"] = null
print("pb-holdout null", {k: round(v["mean"], 3) for k, v in null.items()})
json.dump(res, open(os.path.join(OUT, "defense_stats.json"), "w"), indent=1)
