#!/usr/bin/env python3
"""Robustness of coordinated cover: network jitter, bridge CPU load, slow hosts.

Captures in $ROBUST_DIR (default /tmp/pqm/robust), four runs of 500 connections per
configuration and condition (PQM_SET=robust or slow):
  jit{J}_r{1..4}   path with per-chunk exponential queueing delay of mean J us, from a
                   separate relay process (cmd/pqm-jitter-relay), captured on the
                   client's side of the path (relay port = bridge port + 50)
  load{L}_r{1..4}  L busy-loop processes competing with the bridge for the 2 vCPUs
  slow_r{1..4}     normal hosts and hosts with 4x processing time, offsets 2 and 6 ms
All results are leave-one-run-out: train on three runs, test on the fourth.
Per-bridge results come with a null (transport labels shuffled within each run).
Output: results/robust.json
"""
import json, os, importlib.util
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import roc_auc_score

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("RESULTS_DIR", os.path.join(HERE, "results"))
D = os.environ.get("ROBUST_DIR", "/tmp/pqm/robust")
RUNS = (1, 2, 3, 4)
spec = importlib.util.spec_from_file_location("cs", os.path.join(HERE, "censor_sim.py"))
cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)
rng = np.random.default_rng(5)
ALL, DELAY = [0, 1, 2, 3, 4], [4]


def load(prefix, ports):
    cs.PORTS = ports
    return [cs.features(f"{D}/{prefix}_r{r}.pcap") for r in RUNS]


def gbt():
    return HistGradientBoostingClassifier(max_iter=200, random_state=0)


def fit_auc(X, y, Xt, yt):
    return float(roc_auc_score(yt, gbt().fit(X, y).predict_proba(Xt)[:, 1]))


def single(F, a, b, cols):
    v = []
    for h in range(len(F)):
        tr = [i for i in range(len(F)) if i != h]
        A = np.vstack([F[i][a] for i in tr]); B = np.vstack([F[i][b] for i in tr])
        X = np.vstack([A, B])[:, cols]; y = np.r_[np.zeros(len(A)), np.ones(len(B))]
        Xt = np.vstack([F[h][a], F[h][b]])[:, cols]; yt = np.r_[np.zeros(len(F[h][a])), np.ones(len(F[h][b]))]
        v.append(fit_auc(X, y, Xt, yt))
    return float(np.mean(v)), float(np.std(v, ddof=1))


def bridges(P, k, m, S=None, phi=0.0):
    """m bridges of k distinct connections from pool P (or, w.p. phi, from slow pool S)."""
    idx = np.argsort(rng.random((m, len(P))), axis=1)[:, :k]
    G = P[idx]
    if S is not None and phi > 0:
        slow = rng.random(m) < phi
        if slow.any():
            si = np.argsort(rng.random((int(slow.sum()), len(S))), axis=1)[:, :k]
            G[slow] = S[si]
    return np.column_stack([G[:, :, 0].min(1), G[:, :, 1].min(1), G[:, :, 0].mean(1), G[:, :, 1].mean(1),
                            G[:, :, 2].min(1), G[:, :, 3].min(1),
                            G[:, :, 4].min(1), np.median(G[:, :, 4], 1), G[:, :, 4].mean(1)])


def per_bridge(F, a, b, k, m=1000, reps=2, shuffle=False, slow=None, phi=0.0):
    """Leave-one-run-out per-bridge AUC. slow=(as, bs) names of slow-host configs."""
    def pools(i):
        A, B = F[i][a], F[i][b]
        As = F[i][slow[0]] if slow else None; Bs = F[i][slow[1]] if slow else None
        if shuffle:
            X = np.vstack([A, B]); p = rng.permutation(len(X)); A, B = X[p[:len(A)]], X[p[len(A):]]
        return A, B, As, Bs
    v = []
    for h in range(len(F)):
        tr = [i for i in range(len(F)) if i != h]
        Ps = [pools(i) for i in tr]
        A = np.vstack([p[0] for p in Ps]); B = np.vstack([p[1] for p in Ps])
        As = np.vstack([p[2] for p in Ps]) if slow else None; Bs = np.vstack([p[3] for p in Ps]) if slow else None
        At, Bt, Ast, Bst = pools(h)
        for _ in range(reps):
            X = np.vstack([bridges(A, k, m, As, phi), bridges(B, k, m, Bs, phi)])
            Xt = np.vstack([bridges(At, k, m, Ast, phi), bridges(Bt, k, m, Bst, phi)])
            y = np.r_[np.zeros(m), np.ones(m)]
            v.append(fit_auc(X, y, Xt, y))
    return {"mean": float(np.mean(v)), "sd": float(np.std(v, ddof=1))}


def condition(F, pairs):
    e = {}
    for name, (a, b) in pairs.items():
        e[name] = {"single_both": single(F, a, b, ALL), "single_delay": single(F, a, b, DELAY),
                   "pb5": per_bridge(F, a, b, 5), "pb20": per_bridge(F, a, b, 20)}
    a, b = pairs["coordinated"]
    e["null_pb20"] = per_bridge(F, a, b, 20, shuffle=True)
    e["delay_ms"] = {k: [float(np.percentile(np.concatenate([f[k][:, 4] for f in F]), q)) for q in (50, 99)]
                     for k in F[0]}
    return e


def show(tag, e):
    print(tag, {n: (round(v["single_both"][0], 3), round(v["single_delay"][0], 3), round(v["pb5"]["mean"], 3),
                    round(v["pb20"]["mean"], 3)) for n, v in e.items() if n in ("none", "coordinated")},
          "null20", round(e["null_pb20"]["mean"], 3), round(e["null_pb20"]["sd"], 3), flush=True)


PAIRS = {"none": ("obfs4", "pq-uniform"), "coordinated": ("obfs4-coord", "pq-coord")}
res = {"runs": len(RUNS), "jitter": {}, "load": {}, "slow": {}}
RELAY = {20150: "obfs4", 20350: "pq-uniform", 20850: "obfs4-coord", 20950: "pq-coord"}
for j in (0, 100, 250, 500, 1000, 2000):
    res["jitter"][str(j)] = e = condition(load(f"jit{j}", RELAY), PAIRS); show(f"jitter {j}", e)
SRV = {20100: "obfs4", 20300: "pq-uniform", 20800: "obfs4-coord", 20900: "pq-coord"}
for L in (1, 2, 4):
    F = load(f"load{L}", SRV)
    res["load"][str(L)] = e = condition(F, PAIRS)
    e["p_exceeds_2ms"] = {k: float(np.mean(np.concatenate([f[k][:, 4] for f in F]) > 2.0)) for k in ("obfs4", "pq-uniform")}
    show(f"load {L}", e); print("   P(delay > 2 ms) undefended", e["p_exceeds_2ms"])
SL = {20800: "obfs4-coord", 20900: "pq-coord", 21200: "obfs4-coord-slow", 21300: "pq-coord-slow",
      21400: "obfs4-t6", 21500: "pq-t6", 21600: "obfs4-t6-slow", 21700: "pq-t6-slow"}
F = load("slow", SL)
res["slow"]["delay_ms"] = {k: [float(np.percentile(np.concatenate([f[k][:, 4] for f in F]), q)) for q in (50, 99)] for k in SL.values()}
for T, (an, bn, asn, bsn) in {"2": ("obfs4-coord", "pq-coord", "obfs4-coord-slow", "pq-coord-slow"),
                              "6": ("obfs4-t6", "pq-t6", "obfs4-t6-slow", "pq-t6-slow")}.items():
    e = {"single_normal": single(F, an, bn, ALL), "single_slow": single(F, asn, bsn, ALL), "pb20_vs_phi": {}}
    for phi in (0.0, 0.1, 0.2, 0.5, 1.0):
        e["pb20_vs_phi"][str(phi)] = per_bridge(F, an, bn, 20, slow=(asn, bsn), phi=phi)
    e["null_pb20"] = per_bridge(F, an, bn, 20, shuffle=True)
    res["slow"]["T" + T] = e
    print("slow T", T, round(e["single_normal"][0], 3), round(e["single_slow"][0], 3),
          {p: round(v["mean"], 3) for p, v in e["pb20_vs_phi"].items()}, "null", round(e["null_pb20"]["mean"], 3), flush=True)
print({k: [round(x, 2) for x in v] for k, v in res["slow"]["delay_ms"].items()})
json.dump(res, open(os.path.join(OUT, "robust.json"), "w"), indent=1)
