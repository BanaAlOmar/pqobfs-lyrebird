#!/usr/bin/env python3
"""Length-domain analysis: measured first flights and a length-aware censor.

Parses the loopback capture of the connection experiment (full lyrebird
connection path), extracts the first flight in each direction and its TCP
segment count, checks them against the analytic padding laws, and evaluates
how a censor that sees only first-flight lengths separates pq-obfs bridges
from classical obfs4 bridges under each cover policy.
"""
import json, math, os, sys
from collections import defaultdict
import dpkt, numpy as np

PCAP = os.environ.get("PCAP", "/tmp/pqm/firstflights.pcap")
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
PORTS = {20100: "obfs4", 20200: "pq-fixed", 20300: "pq-uniform", 20400: "pq-uniform-hide"}
MAXH = 8192
SEED_FRAME = 45  # obfs4 inline PRNG-seed frame: 2+16 framing, 3 packet header, 24 seed

# Analytic first-flight supports (total bytes on the wire).
LAW = {
    "obfs4":           {"client": (141, MAXH), "server": (141, MAXH)},
    "pq-fixed":        {"client": (4112, 4112), "server": (4112, 4112)},
    "pq-uniform":      {"client": (2440, MAXH), "server": (1316 + SEED_FRAME, MAXH)},
    "pq-uniform-hide": {"client": (3220, MAXH), "server": (1722 + SEED_FRAME, MAXH)},
}

def flights(pcap):
    conns = defaultdict(list)
    with open(pcap, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            # Loopback captures on Linux use DLT_EN10MB with zero MACs.
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP):
                    continue
            except Exception:
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            ip_len = ip.len - ip.hl * 4 - tcp.off * 4
            if ip_len <= 0:
                continue
            if tcp.dport in PORTS:
                key, d = (tcp.sport, tcp.dport), "c"
            elif tcp.sport in PORTS:
                key, d = (tcp.dport, tcp.sport), "s"
            else:
                continue
            conns[key].append((d, ip_len, tcp.seq))
    out = defaultdict(lambda: {"client": [], "server": [], "cseg": [], "sseg": []})
    for (cport, sport), pk in conns.items():
        # Drop retransmissions (same direction and sequence number).
        seen, clean = set(), []
        for d, n, seq in pk:
            if (d, seq) in seen:
                continue
            seen.add((d, seq)); clean.append((d, n))
        # client first flight: client payload before first server payload
        i = 0; c = cs = 0
        while i < len(clean) and clean[i][0] == "c":
            c += clean[i][1]; cs += 1; i += 1
        s = ss = 0
        while i < len(clean) and clean[i][0] == "s":
            s += clean[i][1]; ss += 1; i += 1
        if c and s:
            t = PORTS[sport]
            out[t]["client"].append(c); out[t]["server"].append(s)
            out[t]["cseg"].append(cs); out[t]["sseg"].append(ss)
    return out

def uniform_pmf_ge(lo, hi, x):
    """P(L >= x) for L uniform on integers [lo, hi]."""
    if x <= lo: return 1.0
    if x > hi: return 0.0
    return (hi - x + 1) / (hi - lo + 1)

def main():
    os.makedirs(OUT, exist_ok=True)
    fl = flights(PCAP)
    res = {"measured": {}, "law_check": {}, "adversary": {}}
    for t, d in fl.items():
        c, s = np.array(d["client"]), np.array(d["server"])
        res["measured"][t] = {
            "n": int(len(c)),
            "client_min": int(c.min()), "client_max": int(c.max()), "client_mean": float(c.mean()),
            "server_min": int(s.min()), "server_max": int(s.max()), "server_mean": float(s.mean()),
            "client_segments": {int(k): int(v) for k, v in zip(*np.unique(d["cseg"], return_counts=True))},
            "server_segments": {int(k): int(v) for k, v in zip(*np.unique(d["sseg"], return_counts=True))},
            "client_unique": int(len(np.unique(c))), "server_unique": int(len(np.unique(s))),
        }
        lo_c, hi_c = LAW[t]["client"]; lo_s, hi_s = LAW[t]["server"]
        ok = bool(((c >= lo_c) & (c <= hi_c)).all() and ((s >= lo_s) & (s <= hi_s)).all())
        res["law_check"][t] = ok
    np.savez(os.path.join(OUT, "flights.npz"),
             **{f"{t}_{k}": np.array(v) for t, d in fl.items() for k, v in d.items()})

    # ---- Length-aware censor: pq-obfs bridge vs classical obfs4 bridge ----
    # Per connection the censor observes (client first-flight length, server
    # first-flight length). Fixed policy: test "both equal 4112".
    lo_o, hi_o = LAW["obfs4"]["client"]
    p_obfs4_4112 = 1 / (hi_o - lo_o + 1)
    adv = {}
    adv["pq-fixed"] = {
        "test": "client and server first flights both equal 4112 B",
        "tpr_1conn": 1.0,
        "fpr_1conn_vs_obfs4": p_obfs4_4112 ** 2,
        "fpr_1conn_client_only": p_obfs4_4112,
        "connections_for_fpr_1e-2": 1, "connections_for_fpr_1e-3": 1,
    }
    for t in ["pq-uniform", "pq-uniform-hide"]:
        lc, ls = LAW[t]["client"][0], LAW[t]["server"][0]
        # Uniform-policy bridges never emit flights below the floors; obfs4
        # does. Most powerful test given n connections: all n flights at or
        # above both floors (likelihood ratio is constant above the floors).
        p_c = uniform_pmf_ge(lo_o, hi_o, lc)
        p_s = uniform_pmf_ge(lo_o, hi_o, ls)
        p = p_c * p_s
        need = lambda a: math.ceil(math.log(a) / math.log(p))
        need_c = lambda a: math.ceil(math.log(a) / math.log(p_c))
        # Single-connection AUC of the optimal (min-length) score.
        auc1 = 0.5 + 0.5 * (1 - p)
        curve = {n: p ** n for n in range(1, 31)}
        adv[t] = {
            "test": f"all first flights >= floors (client {lc} B, server {ls} B)",
            "tpr": 1.0,
            "obfs4_pass_prob_per_conn_client": p_c,
            "obfs4_pass_prob_per_conn_server": p_s,
            "obfs4_pass_prob_per_conn_both": p,
            "fpr_1conn": p,
            "auc_1conn": auc1,
            "connections_for_fpr_1e-2": need(1e-2), "connections_for_fpr_1e-3": need(1e-3),
            "connections_for_fpr_1e-2_client_only": need_c(1e-2),
            "connections_for_fpr_1e-3_client_only": need_c(1e-3),
            "fpr_vs_connections": curve,
        }
    # Base-rate view for the fixed policy against classical obfs4 flows.
    for pi in [1e-1, 1e-2, 1e-3]:
        fpr = adv["pq-fixed"]["fpr_1conn_vs_obfs4"]
        adv["pq-fixed"][f"precision_at_prevalence_{pi:g}"] = pi / (pi + (1 - pi) * fpr)
    res["adversary"] = adv

    # TCP segment counts for each policy over a 1448-byte MSS (timestamps on).
    mss = 1448
    seg = {}
    for t, law in LAW.items():
        lo, hi = law["client"]
        seg[t] = sorted({math.ceil(x / mss) for x in range(lo, hi + 1)})
    res["segment_support_client"] = seg
    json.dump(res, open(os.path.join(OUT, "lengths.json"), "w"), indent=1)
    print(json.dumps({k: res[k] for k in ["measured", "law_check"]}, indent=1))
    print(json.dumps({t: {k: v for k, v in a.items() if k != "fpr_vs_connections"} for t, a in adv.items()}, indent=1))

if __name__ == "__main__":
    main()
