#!/usr/bin/env python3
"""Stress tests of the length defense: a trained classifier and a stateful,
per-bridge censor, on first flights captured from the full connection path.

The classifier is an *evaluation adversary*: gradient-boosted trees on
per-connection features (first-flight lengths and segment counts in both
directions, optionally the bridge's response delay), 5-fold cross-validated
AUC for separating each pq-obfs cover policy from classical obfs4. The
stateful censor aggregates k connections to one bridge.
"""
import json, os
from collections import defaultdict
import dpkt, numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold

PCAP = os.environ.get("PCAP", "/tmp/pqm/firstflights.pcap")
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
PORTS = {20100: "obfs4", 20200: "pq-fixed", 20300: "pq-uniform", 20400: "pq-uniform-hide"}
rng = np.random.default_rng(7)

def features(pcap):
    conns = defaultdict(list)
    for ts, buf in dpkt.pcap.Reader(open(pcap, "rb")):
        try:
            ip = dpkt.ethernet.Ethernet(buf).data
            tcp = ip.data
        except Exception:
            continue
        if not isinstance(tcp, dpkt.tcp.TCP):
            continue
        n = ip.len - ip.hl * 4 - tcp.off * 4
        if n <= 0:
            continue
        if tcp.dport in PORTS:
            conns[(tcp.sport, tcp.dport)].append(("c", n, ts, tcp.seq))
        elif tcp.sport in PORTS:
            conns[(tcp.dport, tcp.sport)].append(("s", n, ts, tcp.seq))
    out = defaultdict(list)
    for (cp, sp), pk in conns.items():
        seen, cl = set(), []
        for d, n, ts, seq in pk:
            if (d, seq) not in seen:
                seen.add((d, seq)); cl.append((d, n, ts))
        i = 0; c = cs = 0; t_last_c = None
        while i < len(cl) and cl[i][0] == "c":
            c += cl[i][1]; cs += 1; t_last_c = cl[i][2]; i += 1
        s = ss = 0; t_first_s = cl[i][2] if i < len(cl) else None
        while i < len(cl) and cl[i][0] == "s":
            s += cl[i][1]; ss += 1; i += 1
        if c and s:
            out[PORTS[sp]].append([c, s, cs, ss, 1e3 * (t_first_s - t_last_c)])
    return {k: np.array(v, dtype=float) for k, v in out.items()}

def cv_auc(X0, X1):
    X = np.vstack([X0, X1]); y = np.r_[np.zeros(len(X0)), np.ones(len(X1))]
    clf = HistGradientBoostingClassifier(max_iter=200, random_state=0)
    s = cross_val_score(clf, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=0), scoring="roc_auc")
    return float(s.mean()), float(s.std())

def bridges(F, k, m):
    """m synthetic bridges, each observed over k distinct connections drawn from F."""
    idx = np.argsort(rng.random((m, len(F))), axis=1)[:, :k]
    G = F[idx]  # m x k x f
    return np.column_stack([G[:, :, 0].min(1), G[:, :, 1].min(1), G[:, :, 0].mean(1), G[:, :, 1].mean(1),
                            G[:, :, 2].min(1), G[:, :, 3].min(1)])

def split_auc(A, B, k, reps=5, m=1000):
    """Per-bridge AUC with disjoint connection pools: training bridges are
    built from one half of each class's connections, test bridges from the
    other half, so no connection appears in both."""
    from sklearn.metrics import roc_auc_score
    aucs = []
    for _ in range(reps):
        pa, pb = rng.permutation(len(A)), rng.permutation(len(B))
        A1, A2 = A[pa[: len(A) // 2]], A[pa[len(A) // 2:]]
        B1, B2 = B[pb[: len(B) // 2]], B[pb[len(B) // 2:]]
        Xtr = np.vstack([bridges(A1, k, m), bridges(B1, k, m)])
        Xte = np.vstack([bridges(A2, k, m), bridges(B2, k, m)])
        y = np.r_[np.zeros(m), np.ones(m)]
        clf = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(Xtr, y)
        aucs.append(roc_auc_score(y, clf.predict_proba(Xte)[:, 1]))
    return float(np.mean(aucs)), float(np.std(aucs))

def main():
    F = features(PCAP)
    res = {"n_per_config": {k: len(v) for k, v in F.items()},
           "median_bridge_delay_ms": {k: float(np.median(v[:, 4])) for k, v in F.items()},
           "single_connection": {}, "per_bridge": {}}
    for t in ["pq-fixed", "pq-uniform", "pq-uniform-hide"]:
        lens = cv_auc(F["obfs4"][:, :4], F[t][:, :4])
        timing = cv_auc(F["obfs4"][:, 4:5], F[t][:, 4:5])
        both = cv_auc(F["obfs4"], F[t])
        res["single_connection"][t] = {"lengths_auc": lens, "delay_only_auc": timing, "lengths_and_delay_auc": both}
        per = {}
        for k in [1, 2, 5, 10, 20]:
            per[k] = split_auc(F["obfs4"][:, :4], F[t][:, :4], k)
        res["per_bridge"][t] = per
        print(t, res["single_connection"][t], {k: round(v[0], 3) for k, v in per.items()}, flush=True)

    # Time to detection for the optimal length test (lengths.json), as a
    # function of the bridge's connection rate and the censor's sampling.
    L = json.load(open(os.path.join(OUT, "lengths.json")))
    ttd = {}
    for t in ["pq-uniform", "pq-uniform-hide"]:
        n2 = L["adversary"][t]["connections_for_fpr_1e-2"]
        n3 = L["adversary"][t]["connections_for_fpr_1e-3"]
        ttd[t] = {f"rate{lam}_sample{f}": {"hours_fpr_1e-2": n2 / (lam * f), "hours_fpr_1e-3": n3 / (lam * f)}
                  for lam in [1, 10, 100] for f in [1.0, 0.1]}
    res["time_to_detection"] = ttd
    # False flags among classical obfs4 bridges for a censor that flags any
    # bridge after n connections at or above the floors.
    p = L["adversary"]["pq-uniform"]["obfs4_pass_prob_per_conn_both"]
    res["obfs4_false_flags_per_1000_bridges"] = {n: 1000 * p ** n for n in [5, 10, 14, 20]}
    json.dump(res, open(os.path.join(OUT, "censor_sim.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
