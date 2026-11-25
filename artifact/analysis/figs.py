#!/usr/bin/env python3
"""Figures for the revised manuscript, from the result files only."""
import json, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from scipy import stats as st

R = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
PQM = os.environ.get("PQM_OUT", "/tmp/pqm")
F = os.environ.get("FIG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "figs"))
os.makedirs(F, exist_ok=True)

plt.rcParams.update({
    "pdf.fonttype": 42, "ps.fonttype": 42,  # embed TrueType, not Type 3
    "font.family": "serif", "font.size": 9, "axes.labelsize": 9, "legend.fontsize": 8,
    "xtick.labelsize": 8, "ytick.labelsize": 8, "axes.spines.top": False,
    "axes.spines.right": False, "figure.dpi": 150, "savefig.bbox": "tight",
})
# One palette for every figure: black, blue, red, and gray as the neutral fourth color.
BLACK, BLUE, RED, GRAY = "#1a1a1a", "#1f4e9c", "#c0392b", "#8c8c8c"
C_RAW, C_ENC, C_NULL, C_OBFS, C_GUIDE = RED, BLUE, BLACK, BLACK, GRAY
C_POL = {"obfs4": BLACK, "pq-fixed": RED, "pq-uniform": BLUE, "pq-uniform-hide": GRAY}
LBL = {"obfs4": "obfs4", "pq-fixed": "pq-obfs fixed", "pq-uniform": "pq-obfs uniform",
       "pq-uniform-hide": "pq-obfs uniform-hide"}
W = 6.9
S = json.load(open(f"{R}/stats.json"))
pc = np.load(f"{R}/popcount.npz")

# ---------------------------------------------------------- distributions
fig, ax = plt.subplots(1, 2, figsize=(W, 2.4))
k = np.arange(250, 450)
ax[0].hist(pc["msb_raw"], bins=np.arange(250, 450, 3), density=True, color=C_RAW, alpha=.55, label="raw keys")
ax[0].hist(pc["msb_enc"], bins=np.arange(250, 450, 3), density=True, color=C_ENC, alpha=.55, label="encoded keys")
ax[0].plot(k, st.binom.pmf(k, 768, .5), color=C_NULL, lw=1, label="null Bin(768, 1/2)")
lo, hi = S["analytic"]["msb_bounds"]
ax[0].axvspan(lo, hi, color=BLUE, alpha=.06, lw=0)
ax[0].axvline(lo, color=C_GUIDE, ls=":", lw=.8); ax[0].axvline(hi, color=C_GUIDE, ls=":", lw=.8)
ax[0].set_xlabel(r"MSB count $K_{\mathrm{msb}}$ per key"); ax[0].set_ylabel("density")
ax[0].set_ylim(0, ax[0].get_ylim()[1] * 1.35); ax[0].legend(frameon=False, loc="upper left")
k = np.arange(150, 290)
ax[1].hist(pc["k4_raw"], bins=np.arange(150, 290, 2), density=True, color=C_RAW, alpha=.55, label="raw ciphertexts")
ax[1].hist(pc["k4_enc"], bins=np.arange(150, 290, 2), density=True, color=C_ENC, alpha=.55, label="encoded ciphertexts")
ax[1].plot(k, st.binom.pmf(k, 768, 257 / 1024), color=C_NULL, lw=1, label="null Bin(768, 257/1024)")
ax[1].axvline(S["analytic"]["mf_k4_crit"], color=C_GUIDE, ls=":", lw=.8)
ax[1].set_xlabel(r"four-preimage count $K_4$ per ciphertext"); ax[1].set_ylim(0, ax[1].get_ylim()[1] * 1.35); ax[1].legend(frameon=False, loc="upper left")
fig.tight_layout(); fig.savefig(f"{F}/distributions.pdf"); plt.close(fig)

# --------------------------------------------------------------------- ROC
roc = np.load(f"{R}/roc.npz")
fig, ax = plt.subplots(1, 2, figsize=(W, 2.7))
for key, lab, c in [("msb", "MSB test, 1 key", BLACK), ("mf_1ct", "matched filter, 1 ciphertext", RED),
                    ("mf_2ct", "matched filter, 2 ciphertexts", BLUE)]:
    f, t = roc[key + "_f"], roc[key + "_t"]
    o = np.argsort(f); f, t = f[o], t[o]
    m = f > 1e-9
    ax[0].plot(f[m], t[m], color=c, lw=1.2, label=f"{lab} (AUC {S['auc'][key]:.3f})")
_g = np.logspace(-6, 0, 400)  # chance line y = x, sampled densely so it is correct on a log axis
ax[0].plot(_g, _g, color=C_GUIDE, lw=.8, ls="--", label="chance ($y=x$)")
ax[0].set_xscale("log"); ax[0].set_xlim(1e-6, 1); ax[0].set_ylim(0, 1.01)
ax[0].axvline(1e-3, color=C_GUIDE, ls=":", lw=.8)
ax[0].set_xlabel("false-positive rate (uniform input)"); ax[0].set_ylabel("detection rate")
h, l = ax[0].get_legend_handles_labels()
fig.legend(h, l, frameon=False, loc="upper center", ncol=4, fontsize=6.5, handlelength=1.5, columnspacing=1.2)
mc = S["analytic"]["mf_detect_vs_ciphertexts"]
ms = np.arange(1, 11)
def det(m):
    n = 768 * m
    kc = int(st.binom.isf(1e-3, n, 257 / 1024))
    while st.binom.sf(kc - 1, n, 257 / 1024) > 1e-3: kc += 1
    return st.binom.sf(kc - 1, n, 1028 / 3329)
ax[1].plot(ms, [det(m) for m in ms], "o-", color=C_RAW, ms=3, lw=1)
ax[1].axvline(2, color=C_GUIDE, ls=":", lw=.8); ax[1].text(2.25, .75, "one connection\n($c_S$ and $c_e$)", fontsize=7)
ax[1].set_xlabel("raw ciphertexts observed"); ax[1].set_ylabel(r"detection at $\alpha=10^{-3}$")
ax[1].set_ylim(0.6, 1.005)
ax[1].set_xticks(range(1, 11))
fig.tight_layout(rect=(0, 0, 1, 0.9)); fig.savefig(f"{F}/roc.pdf"); plt.close(fig)

# ----------------------------------------------------------------- lengths
fl = np.load(f"{R}/flights.npz")
L = json.load(open(f"{R}/lengths.json"))
fig, ax = plt.subplots(1, 2, figsize=(W, 2.7))
bins = np.arange(0, 8193 + 256, 256)
for i, t in enumerate(["obfs4", "pq-uniform", "pq-uniform-hide"]):
    ax[0].hist(fl[f"{t}_client"], bins=bins, histtype="step", lw=1.2, color=C_POL[t], label=LBL[t])
ax[0].axvline(4112, color=C_POL["pq-fixed"], lw=1.2, label="pq-obfs fixed (all 500)")
ax[0].set_xlabel("client first-flight length (bytes)"); ax[0].set_ylabel("connections per 256-B bin")
n = np.arange(1, 31)
ax[1].semilogy([1], [L["adversary"]["pq-fixed"]["fpr_1conn_vs_obfs4"]], "s", color=C_POL["pq-fixed"])
for t in ["pq-uniform", "pq-uniform-hide"]:
    a = L["adversary"][t]
    ax[1].semilogy(n, a["obfs4_pass_prob_per_conn_both"] ** n, "-", color=C_POL[t], lw=1.2, )
    ax[1].semilogy(n, a["obfs4_pass_prob_per_conn_client"] ** n, "--", color=C_POL[t], lw=1, )
for y, lab in [(1e-2, "$10^{-2}$"), (1e-3, "$10^{-3}$")]:
    ax[1].axhline(y, color=C_GUIDE, ls=":", lw=.7)
    ax[1].text(30.6, y, lab, va="center", ha="left", fontsize=6.5, color=C_GUIDE)
ax[1].set_xlabel("connections observed to one bridge"); ax[1].set_ylabel("false-positive rate vs. obfs4")
ax[1].set_ylim(1e-9, 1.5); ax[1].set_xlim(0, 31)
from matplotlib.lines import Line2D
ax[1].legend([Line2D([], [], color=BLACK, lw=1.2), Line2D([], [], color=BLACK, lw=1, ls="--")],
             ["both directions", "client direction only"], frameon=False, fontsize=6.5, loc="lower left", bbox_to_anchor=(0.12, 0.02))
h, l = ax[0].get_legend_handles_labels()
fig.legend(h, l, frameon=False, loc="upper center", ncol=4, fontsize=7, handlelength=1.5, columnspacing=1.2)
fig.tight_layout(rect=(0, 0, 1, 0.92)); fig.savefig(f"{F}/lengths.pdf"); plt.close(fig)

# ----------------------------------------------------------------- latency
labels = [("rtt0", 0), ("rtt50", 50), ("rtt150", 150), ("rtt300", 300)]
lat = {l: json.load(open(f"{PQM}/conn_latency_{l}.json")) for l, _ in labels if os.path.exists(f"{PQM}/conn_latency_{l}.json")}
fig, ax = plt.subplots(1, 2, figsize=(W, 2.4))
for t in ["obfs4", "pq-fixed", "pq-uniform", "pq-uniform-hide"]:
    x = np.sort([s["handshake_us"] / 1e3 for s in lat["rtt0"][t]])
    ax[0].plot(x, np.arange(1, len(x) + 1) / len(x), color=C_POL[t], lw=1.2, label=LBL[t])
ax[0].set_xlabel("handshake latency, loopback (ms)"); ax[0].set_ylabel("ECDF"); ax[0].set_xlim(0.5, 3)
ax[0].legend(frameon=False, loc="lower right")
rng = np.random.default_rng(1)
def boot_delta(x, y, B=2000):
    d = [np.median(rng.choice(y, len(y))) - np.median(rng.choice(x, len(x))) for _ in range(B)]
    return np.median(y) - np.median(x), np.percentile(d, 2.5), np.percentile(d, 97.5)
off = {"pq-fixed": -0.18, "pq-uniform": 0, "pq-uniform-hide": 0.18}
rtts = [r for l, r in labels]
for t in ["pq-fixed", "pq-uniform", "pq-uniform-hide"]:
    xs, md, lo, hi = [], [], [], []
    for l, rtt in labels:
        if l not in lat: continue
        x = np.array([s["handshake_us"] / 1e3 for s in lat[l]["obfs4"]])
        y = np.array([s["handshake_us"] / 1e3 for s in lat[l][t]])
        dm, dl, dh = boot_delta(x, y)
        xs.append(rtts.index(rtt) + off[t]); md.append(dm); lo.append(dl); hi.append(dh)
    md, lo, hi = map(np.array, (md, lo, hi))
    ax[1].errorbar(xs, md, yerr=[md - lo, hi - md], fmt="o", ms=3, color=C_POL[t], lw=1, capsize=2, label=LBL[t])
ax[1].axhline(0, color=C_GUIDE, lw=.6)
ax[1].set_xlabel("round-trip time (emulated except loopback)")
ax[1].set_ylabel("median latency over obfs4 (ms)")
ax[1].set_xticks(range(len(rtts))); ax[1].set_xticklabels(["loopback"] + [f"{r} ms" for r in rtts[1:]]); ax[1].set_xlim(-0.5, len(rtts) - 0.5)
fig.tight_layout(); fig.savefig(f"{F}/latency.pdf"); plt.close(fig)

# ------------------------------------------------------------------- 6-bit
# One panel, one scale: for each unused bit, the fraction of encodings in
# which it is set (0.5 for a conforming encoder), with Wilson 95% intervals.
r6, g6 = np.load(f"{R}/six_rust.npy"), np.load(f"{R}/six_go.npy")
RV = os.environ.get("RUST_VECTORS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "rust_vectors.json"))
rk6 = np.array([(bytes.fromhex(json.loads(l)["ek_kmln"])[1123] & 0xFC) >> 2 for l in open(RV)])
def wilson(k, n, z=1.96):
    p = k / n; d = 1 + z * z / n; c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return c - h, c + h
series = [("Rust reference, keys", rk6, GRAY), ("Rust reference, ciphertexts", r6, RED),
          ("This work, ciphertexts", g6, BLUE)]
fig, ax = plt.subplots(figsize=(3.4, 2.5))  # one column of the two-column layout
x = np.arange(6); w = 0.27
for i, (lbl, v, col) in enumerate(series):
    k = np.array([((v >> b) & 1).sum() for b in range(6)]); n = len(v)
    lo, hi = wilson(k, n); f = k / n
    if k.sum() == 0:   # a stuck bit: draw a marker, a zero-height bar is invisible
        ax.errorbar(x + (i - 1) * w, f, yerr=[f - lo, hi - f], fmt="D", ms=4, color=col, ecolor=col,
                    lw=0.7, capsize=1.5, clip_on=False, zorder=5,
                    label=f"{lbl}: never set ({n:,})")
    else:
        ax.bar(x + (i - 1) * w, f, w, color=col, label=f"{lbl} ({n:,})",
               yerr=[f - lo, hi - f], error_kw=dict(lw=0.7, capsize=1.5, ecolor=BLACK))
ax.axhline(0.5, color=C_GUIDE, ls="--", lw=0.8, zorder=0)
ax.set_xticks(x); ax.set_xticklabels([f"{b + 2}" for b in range(6)])
ax.set_xlabel("unused bit (of accumulator byte 1,123)")
ax.set_ylabel("fraction with bit set"); ax.set_ylim(0, 1.05); ax.set_xlim(-0.55, 5.55)
ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
ax.legend(frameon=False, loc="upper center", ncol=1, fontsize=6.8, handlelength=1.2, borderaxespad=0.1)
fig.tight_layout(); fig.savefig(f"{F}/sixbit.pdf"); plt.close(fig)

# ------------------------------------------------- stateful censor and delay
import importlib.util
CS = json.load(open(f"{R}/censor_sim.json"))
fig, ax = plt.subplots(1, 2, figsize=(W, 2.3))
for t in ["pq-fixed", "pq-uniform", "pq-uniform-hide"]:
    ks = sorted(int(k) for k in CS["per_bridge"][t])
    m = [CS["per_bridge"][t][str(k)][0] for k in ks]; e = [CS["per_bridge"][t][str(k)][1] for k in ks]
    ax[0].errorbar(ks, m, yerr=e, marker="o", ms=3, lw=1, capsize=2, color=C_POL[t], label=LBL[t])
ax[0].set_xscale("log"); ax[0].set_xticks([1, 2, 5, 10, 20]); ax[0].set_xticklabels(["1", "2", "5", "10", "20"])
ax[0].set_xlabel("connections observed per bridge"); ax[0].set_ylabel("AUC vs obfs4 (lengths only)")
ax[0].set_ylim(0.5, 1.02); ax[0].legend(frameon=False, loc="lower right")
spec = importlib.util.spec_from_file_location("cs", os.path.join(os.path.dirname(os.path.abspath(__file__)), "censor_sim.py"))
cs = importlib.util.module_from_spec(spec); spec.loader.exec_module(cs)
FF = cs.features(os.environ.get("PCAP", f"{PQM}/firstflights.pcap"))
for t in ["obfs4", "pq-fixed", "pq-uniform", "pq-uniform-hide"]:
    d = np.sort(FF[t][:, 4]); ax[1].plot(d, np.arange(1, len(d) + 1) / len(d), color=C_POL[t], lw=1.2, label=LBL[t])
ax[1].set_xlim(0, 1.5); ax[1].set_xlabel("bridge response delay on loopback (ms)"); ax[1].set_ylabel("CDF")
fig.tight_layout(); fig.savefig(f"{F}/censor.pdf"); plt.close(fig)
print("figures written to", F)

# ------------------------------------------------------- coordinated cover
D = json.load(open(f"{R}/defense.json"))
DF = np.load(f"{R}/defense_features.npz")
fig, ax = plt.subplots(1, 3, figsize=(W, 2.45), gridspec_kw={"width_ratios": [1.1, 1.05, 1]})
for key, lab, c, ls in [("obfs4", "obfs4", BLACK, "--"), ("pq_uniform", "pq", BLUE, "--"),
                        ("pq_jitter1000", "pq, 1 ms jitter", RED, "-"),
                        ("obfs4_coord", "obfs4, coord.", BLACK, "-"), ("pq_coord", "pq, coord.", BLUE, "-")]:
    v = np.sort(DF[key][:, 4]); ax[0].plot(v, np.arange(1, len(v) + 1) / len(v), color=c, ls=ls, lw=1.1, label=lab)
ax[0].set_xlabel("response delay (ms)"); ax[0].set_ylabel("CDF"); ax[0].set_xlim(0, 3.6)
ax[0].set_ylim(0, 1.5); ax[0].set_yticks([0, .25, .5, .75, 1])
ax[0].legend(frameon=False, loc="upper left", fontsize=6.3, handlelength=1.5, ncol=2, columnspacing=.8)
ST = json.load(open(f"{R}/defense_stats.json"))
names = [("baseline", "none"), ("jitter500", "pq 0.5"), ("jitter1000", "pq 1"), ("jitter2000", "pq 2"),
         ("light", "light"), ("coordinated", "coord.")]
x = np.arange(len(names))
hb = [ST["holdout"][n]["gbt"]["both"] for n, _ in names]
m = [h["auc"] for h in hb]
err = [[h["auc"] - h["ci95"][0] for h in hb], [h["ci95"][1] - h["auc"] for h in hb]]
cols = [BLACK, RED, RED, RED, GRAY, BLUE]
ax[1].bar(x, m, yerr=err, color=cols, width=.62, capsize=2, error_kw={"lw": .8})
ax[1].axhspan(.45, .55, color=GRAY, alpha=.15, lw=0)
ax[1].axhline(.5, color=C_GUIDE, ls=":", lw=.8)
ax[1].set_xticks(x); ax[1].set_xticklabels([l for _, l in names], fontsize=6.8, rotation=40, ha="right", rotation_mode="anchor")
ax[1].set_ylim(.4, 1.0); ax[1].set_ylabel("AUC, one connection")
PB = ST["per_bridge_holdout"]
ks = [1, 2, 5, 10, 20]
nl = PB["null_coordinated"]
ax[2].fill_between(ks, [nl[str(k)]["lo95"] for k in ks], [nl[str(k)]["hi95"] for k in ks], color=GRAY, alpha=.18, lw=0,
                   label="null (95%)")
for n, lab, c, off in [("baseline", "none", BLACK, 1.0), ("light", "light", GRAY, 0.94), ("coordinated", "coordinated", BLUE, 1.06)]:
    cc = PB[n]
    mm = np.array([cc[str(k)]["mean"] for k in ks])
    lo = mm - np.array([cc[str(k)]["lo95"] for k in ks]); hi = np.array([cc[str(k)]["hi95"] for k in ks]) - mm
    ax[2].errorbar(np.array(ks) * off, mm, yerr=[lo, hi], color=c, marker="o", ms=3, lw=1.1, capsize=2, label=lab)
ax[2].axhline(.5, color=C_GUIDE, ls=":", lw=.8)
ax[2].set_xscale("log"); ax[2].set_xticks(ks); ax[2].set_xticklabels([str(k) for k in ks])
ax[2].set_xlabel("connections per bridge $k$"); ax[2].set_ylabel("AUC, per bridge"); ax[2].set_ylim(.2, 1.05)
ax[2].legend(frameon=False, loc="lower left", fontsize=6.3, ncol=2, columnspacing=.8, handlelength=1.2)
for a, t in zip(ax, "abc"): a.set_title(f"({t})", fontsize=8, loc="left")
fig.tight_layout(); fig.savefig(f"{F}/defense.pdf"); plt.close(fig)

# ------------------------------------------------------------- robustness
RB = json.load(open(f"{R}/robust.json"))
fig, ax = plt.subplots(1, 2, figsize=(W, 2.4))
J = RB["jitter"]; js = sorted(J, key=float); x = np.array([float(j) / 1000 for j in js])
xp = np.where(x == 0, 0.05, x)  # draw 0 at 0.05 ms on the log axis
ax[0].plot(xp, [J[j]["none"]["single_delay"][0] for j in js], color=BLACK, ls="--", marker="o", ms=3, lw=1.1, label="no defense, delay only")
ax[0].plot(xp, [J[j]["none"]["single_both"][0] for j in js], color=BLACK, marker="o", ms=3, lw=1.1, label="no defense, all features")
ax[0].plot(xp, [J[j]["coordinated"]["single_both"][0] for j in js], color=BLUE, marker="o", ms=3, lw=1.1, label="coordinated, all features")
ax[0].fill_between(xp, [J[j]["null_pb20"]["mean"] - 2 * J[j]["null_pb20"]["sd"] for j in js],
                   [J[j]["null_pb20"]["mean"] + 2 * J[j]["null_pb20"]["sd"] for j in js], color=GRAY, alpha=.15, lw=0)
ax[0].plot(xp, [J[j]["coordinated"]["pb20"]["mean"] for j in js], color=BLUE, ls=":", marker="s", ms=3, lw=1.1, label="coordinated, per bridge $k=20$")
ax[0].axhline(.5, color=C_GUIDE, ls=":", lw=.8)
ax[0].set_xscale("log"); ax[0].set_xticks(xp); ax[0].set_xticklabels(["0", "0.1", "0.25", "0.5", "1", "2"])
ax[0].set_xlabel("mean path jitter (ms)"); ax[0].set_ylabel("AUC (run holdout)"); ax[0].set_ylim(.35, 1.22)
ax[0].set_yticks([.4, .5, .6, .7, .8, .9, 1.0])
ax[0].legend(frameon=False, fontsize=6.0, loc="upper center", ncol=2, columnspacing=.8, handlelength=1.6)
S = RB["slow"]; ph = ["0.0", "0.1", "0.2", "0.5", "1.0"]; xs = [float(p) for p in ph]
for T, c, lab in [("T2", RED, "$T=2$ ms"), ("T6", BLUE, "$T=6$ ms")]:
    ax[1].errorbar(xs, [S[T]["pb20_vs_phi"][p]["mean"] for p in ph], yerr=[S[T]["pb20_vs_phi"][p]["sd"] for p in ph],
                   color=c, marker="o", ms=3, lw=1.1, capsize=2, label=lab)
nl = np.mean([S[T]["null_pb20"]["mean"] for T in ("T2", "T6")]); ns = np.mean([S[T]["null_pb20"]["sd"] for T in ("T2", "T6")])
ax[1].axhspan(nl - 2 * ns, nl + 2 * ns, color=GRAY, alpha=.15, lw=0, label="null ($\\pm2$ sd)")
ax[1].axhline(.5, color=C_GUIDE, ls=":", lw=.8)
ax[1].set_xlabel("share of bridges on 4$\\times$ slower hosts"); ax[1].set_ylabel("AUC, per bridge, $k=20$"); ax[1].set_ylim(.35, 1.05)
ax[1].legend(frameon=False, fontsize=6.5, loc="upper left")
for a, t in zip(ax, "ab"): a.set_title(f"({t})", fontsize=8, loc="left")
fig.tight_layout(); fig.savefig(f"{F}/robust.pdf"); plt.close(fig)
