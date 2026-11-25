#!/usr/bin/env python3
"""Evaluation of the coordinated-cover defenses (cover_policy.go).

Configurations, captured on the full lyrebird connection path (500 each):
  obfs4, pq-uniform                 baselines
  pq-jitter{500,1000,2000}          pq-obfs bridge adds U[0,J] us after processing
  obfs4-coord, pq-coord             both bridges release at arrival + 2 ms + U[0,1] ms,
                                    obfs4 uses the pq-obfs padding floor 2440:1361
For each comparison we report the trained classifier's single-connection AUC
on lengths, response delay and both, and the per-bridge AUC on all features.
Output: results/defense.json
"""
import json, os
import numpy as np
from scipy import stats as st
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("cs", os.path.join(HERE, "censor_sim.py"))
cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)

PCAP = os.environ.get("DEF_PCAP", "/tmp/pqm/defense.pcap")
LAT = os.environ.get("DEF_LAT", "/tmp/pqm/conn_latency_defense_rtt0.json")
OUT = os.environ.get("RESULTS_DIR", os.path.join(HERE, "results"))
cs.PORTS = {20100: "obfs4", 20300: "pq-uniform", 20500: "pq-jitter500", 20600: "pq-jitter1000",
            20700: "pq-jitter2000", 20800: "obfs4-coord", 20900: "pq-coord", 21000: "obfs4-light", 21100: "pq-light"}
REPS = [r for r in ("r1", "r2", "r3", "r4", "r5") if os.path.exists(f"/tmp/pqm/defense_{r}.pcap")]
rng = np.random.default_rng(11)


def bridges_all(F, k, m):
    """m simulated bridges, each seen over k connections: length and delay summaries."""
    idx = rng.integers(0, len(F), size=(m, k))
    G = F[idx]
    return np.column_stack([G[:, :, 0].min(1), G[:, :, 1].min(1), G[:, :, 0].mean(1), G[:, :, 1].mean(1),
                            G[:, :, 2].min(1), G[:, :, 3].min(1),
                            G[:, :, 4].min(1), np.median(G[:, :, 4], 1), G[:, :, 4].mean(1)])


def split_auc_all(A, B, k, reps=5, m=1000):
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    aucs = []
    for _ in range(reps):
        pa, pb = rng.permutation(len(A)), rng.permutation(len(B))
        A1, A2 = A[pa[: len(A) // 2]], A[pa[len(A) // 2:]]
        B1, B2 = B[pb[: len(B) // 2]], B[pb[len(B) // 2:]]
        Xtr = np.vstack([bridges_all(A1, k, m), bridges_all(B1, k, m)])
        Xte = np.vstack([bridges_all(A2, k, m), bridges_all(B2, k, m)])
        y = np.r_[np.zeros(m), np.ones(m)]
        clf = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(Xtr, y)
        aucs.append(roc_auc_score(y, clf.predict_proba(Xte)[:, 1]))
    return float(np.mean(aucs)), float(np.std(aucs))


def single(A, B):
    return {"lengths_auc": cs.cv_auc(A[:, :4], B[:, :4]),
            "delay_only_auc": cs.cv_auc(A[:, 4:5], B[:, 4:5]),
            "lengths_and_delay_auc": cs.cv_auc(A, B)}


COMPS = {"baseline": ("obfs4", "pq-uniform"), "jitter500": ("obfs4", "pq-jitter500"),
         "jitter1000": ("obfs4", "pq-jitter1000"), "jitter2000": ("obfs4", "pq-jitter2000"),
         "coordinated": ("obfs4-coord", "pq-coord"), "light": ("obfs4-light", "pq-light"),
         "coord_vs_legacy": ("obfs4", "pq-coord")}


def agg(xs):
    a = np.array(xs, dtype=float)
    return [float(a.mean()), float(a.std(ddof=1)) if len(a) > 1 else 0.0]


def main():
    per = []
    for r in REPS:
        F = cs.features(f"/tmp/pqm/defense_{r}.pcap")
        lat = json.load(open(f"/tmp/pqm/conn_latency_defense_{r}.json"))
        one = {"F": F, "lat": lat, "single": {}, "bridge": {}}
        for name, (a, b) in COMPS.items():
            one["single"][name] = single(F[a], F[b])
        for name in ("baseline", "coordinated", "light"):
            a, b = COMPS[name]
            one["bridge"][name] = {k: split_auc_all(F[a], F[b], k, reps=3) for k in (1, 2, 5, 10, 20)}
        per.append(one); print(r, {n: round(v["lengths_and_delay_auc"][0], 3) for n, v in one["single"].items()}, flush=True)
    res = {"replicates": len(per), "n_per_config_per_replicate": {k: len(v) for k, v in per[0]["F"].items()}}
    res["single_connection"] = {n: {m: agg([p["single"][n][m][0] for p in per]) for m in ("lengths_auc", "delay_only_auc", "lengths_and_delay_auc")} for n in COMPS}
    res["per_bridge_all_features"] = {n: {str(k): agg([p["bridge"][n][k][0] for p in per]) for k in (1, 2, 5, 10, 20)} for n in ("baseline", "coordinated", "light")}
    allF = {k: np.vstack([p["F"][k] for p in per]) for k in per[0]["F"]}
    res["delay_ms"] = {k: {**{f"p{q}": float(np.percentile(v[:, 4], q)) for q in (1, 10, 50, 90, 99)}, "mean": float(v[:, 4].mean())} for k, v in allF.items()}
    res["lengths"] = {k: {"client_min": int(v[:, 0].min()), "client_max": int(v[:, 0].max()), "server_min": int(v[:, 1].min()),
                          "server_max": int(v[:, 1].max()), "client_mean": float(v[:, 0].mean()), "server_mean": float(v[:, 1].mean())} for k, v in allF.items()}
    res["ks"] = {}
    for name in ("coordinated", "light"):
        a, b = COMPS[name]
        res["ks"][name] = {nm: float(st.ks_2samp(allF[a][:, c], allF[b][:, c]).pvalue) for c, nm in ((0, "client"), (1, "server"))}
    hs = {}
    for k in per[0]["lat"]:
        v = np.concatenate([[s["handshake_us"] for s in p["lat"][k]] for p in per]) / 1e3
        hs[k] = {"median": float(np.median(v)), "p95": float(np.percentile(v, 95))}
    res["handshake_ms"] = hs
    o, oc = res["lengths"]["obfs4"], res["lengths"]["obfs4-coord"]
    res["obfs4_floor_extra_bytes"] = {"client": oc["client_mean"] - o["client_mean"], "server": oc["server_mean"] - o["server_mean"]}
    res["obfs4_floor_extra_bytes_analytic"] = {"client": (2440 - 141) / 2, "server": (1361 - 141) / 2}
    json.dump(res, open(os.path.join(OUT, "defense.json"), "w"), indent=1)
    np.savez_compressed(os.path.join(OUT, "defense_features.npz"), **{k.replace("-", "_"): v for k, v in allF.items()})
    for n, v in res["single_connection"].items(): print(n, {m: [round(x, 3) for x in y] for m, y in v.items()})
    for n, v in res["per_bridge_all_features"].items(): print(n, {k: round(y[0], 3) for k, y in v.items()})
    print(res["ks"]); print({k: round(v["median"], 2) for k, v in hs.items()}); print(res["obfs4_floor_extra_bytes"])


def features_only():
    """Write the per-connection features (for figures) without re-running the classifiers."""
    allF = {}
    for r in REPS:
        F = cs.features(f"/tmp/pqm/defense_{r}.pcap")
        for k, v in F.items(): allF.setdefault(k, []).append(v)
    allF = {k: np.vstack(v) for k, v in allF.items()}
    np.savez_compressed(os.path.join(OUT, "defense_features.npz"), **{k.replace("-", "_"): v for k, v in allF.items()})


if __name__ == "__main__":
    import sys
    if sys.argv[1:] == ["--features-only"]:
        features_only(); sys.exit()
    main()
