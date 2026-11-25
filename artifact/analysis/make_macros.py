#!/usr/bin/env python3
"""Generate manuscript/results.tex (LaTeX macros) and nist_table.tex from the
result files, so that every number in the paper comes from a measurement."""
import json, math, os, re, statistics as stx
import numpy as np

R = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
PQM = os.environ.get("PQM_OUT", "/tmp/pqm")
MS = os.environ.get("MANUSCRIPT", os.path.join(os.path.dirname(os.path.abspath(__file__)), "manuscript"))

M = {}
def put(name, value):
    assert re.fullmatch(r"[A-Za-z]+", name), name
    M[name] = value

def pct(x, d=1): return f"{100 * x:.{d}f}"
def num(x, d=0):
    s = f"{x:,.{d}f}"
    return s.replace(",", "{,}")
def ci(c, d=2): return f"[{100 * c[0]:.{d}f}, {100 * c[1]:.{d}f}]"

S = json.load(open(f"{R}/stats.json"))
A = S["analytic"]
put("rangeLogTen", f"{A['range_uniform_pass_log10']:.0f}")
put("mfOneExact", pct(A["mf_detect_exact_1ct"]))
put("mfTwoExact", pct(A["mf_detect_vs_ciphertexts"]["2"]))
put("msbMeanRaw", f"{A['msb_mean_raw']:.1f}")
put("msbSep", f"{A['msb_sep_sigma']:.1f}")
put("msbLo", str(A["msb_bounds"][0])); put("msbHi", str(A["msb_bounds"][1]))
put("chiCrit", f"{A['chi2_crit']:.1f}")
put("klNats", f"{A['mf_kl_nats_per_coeff']:.4f}")
put("mfCrit", str(A["mf_k4_crit"]))
put("mfFprExact", f"{100 * A['mf_fpr_exact']:.3f}")
put("msbDetExact", pct(A["msb_detect_exact"], 2))

K = S["keys"]; G = ["kyberpy", "gostd", "circl"]; GN = {"kyberpy": "Kyberpy", "gostd": "Gostd", "circl": "Circl"}
msb_raw = [K[g]["raw"]["msb_test"]["rate"] for g in G]
chi_raw = [K[g]["raw"]["chi2_test"]["rate"] for g in G]
put("msbDetMin", pct(min(msb_raw), 2)); put("msbDetMax", pct(max(msb_raw), 2))
put("chiDetMin", pct(min(chi_raw))); put("chiDetMax", pct(max(chi_raw)))
for g in G:
    for t, key in [("range", "range_test"), ("msb", "msb_test"), ("chi", "chi2_test")]:
        put(f"{t}Raw{GN[g]}", pct(K[g]["raw"][key]["rate"], 2))
        put(f"{t}Enc{GN[g]}", pct(K[g]["encoded"][key]["rate"], 2))
        put(f"{t}Enc{GN[g]}CI", ci(K[g]["encoded"][key]["ci95"]))
put("msbFracRaw", f"{K['circl']['raw']['msb_fraction']:.3f}")
put("msbFracEnc", f"{K['circl']['encoded']['msb_fraction']:.3f}")
put("msbUnif", f"{100 * K['uniform_reference']['msb_test']['rate']:.3f}")

C = S["ciphertexts"]
for g in ["gostd", "circl"]:
    put(f"mfDet{GN[g]}", pct(C[g]["raw"]["matched_filter"]["rate"]))
    put(f"mfEnc{GN[g]}", pct(C[g]["encoded"]["matched_filter"]["rate"], 2))
    put(f"mfEnc{GN[g]}CI", ci(C[g]["encoded"]["matched_filter"]["ci95"]))
    put(f"mfTwo{GN[g]}", pct(C[g]["raw_two_per_connection"]["rate"]))
put("mfUnif", f"{100 * C['uniform_reference_1e6']['rate']:.3f}")
put("aucMfOne", f"{S['auc']['mf_1ct']:.3f}")
put("aucMfTwo", f"{S['auc']['mf_2ct']:.4f}")
put("aucMfEnc", f"{S['auc']['mf_encoded_vs_uniform_empirical']:.3f}")

Ac = S["acceptance"]
put("accEkGostd", f"{Ac['ek_gostd']['rate']:.3f}"); put("accEkCircl", f"{Ac['ek_circl']['rate']:.3f}")
put("accEkKyberpy", f"{Ac['ek_kyberpy']['rate']:.3f}")
put("accEkExact", f"{Ac['ek_exact_spec']:.3f}")
put("accCtGostd", f"{Ac['ct_gostd']['rate']:.3f}"); put("accCtCircl", f"{Ac['ct_circl']['rate']:.3f}")

GF = S["gfw_rules"]
for k, n in [("obfs4 (uniform bytes)", "Obfs"), ("pq-obfs, raw ML-KEM", "Raw"), ("pq-obfs, Kemeleon", "Enc")]:
    put(f"gfwPop{n}", f"{GF[k]['popcount_per_byte']:.2f}")
    put(f"gfw{n}", pct(GF[k]["flagged_as_fully_encrypted"]["rate"], 2))
    put(f"gfw{n}CI", ci(GF[k]["flagged_as_fully_encrypted"]["ci95"]))

SX = S["six_bit"]
put("sixRustCt", f"{SX['rust_ct']['zero']['k']:,} of {SX['rust_ct']['n']:,}".replace(",", "{,}"))
put("sixGoDistinct", str(SX["go_ct"]["distinct_values"]))
put("sixGoP", f"{SX['go_ct']['chi2_64_p']:.2f}")
put("sixRustEkZero", str(SX["rust_ek"]["zero"]["k"]))

# ------------------------------------------------------------------ lengths
L = json.load(open(f"{R}/lengths.json"))
meas = L["measured"]
def rng(t, d): return f"{num(meas[t][d + '_min'])}--{num(meas[t][d + '_max'])}"
def segs(t):
    k = sorted(int(x) for x in meas[t]["client_segments"])
    return f"{k[0]}--{k[-1]}" if len(k) > 1 else str(k[0])
for t, n in [("obfs4", "Obfs"), ("pq-uniform", "Uni"), ("pq-uniform-hide", "Hide")]:
    put(f"len{n}C", rng(t, "client")); put(f"len{n}S", rng(t, "server")); put(f"seg{n}", segs(t))
adv = L["adversary"]
e = adv["pq-fixed"]["fpr_1conn_vs_obfs4"]; ex = math.floor(math.log10(e))
put("pFixed", f"${e / 10 ** ex:.1f}\\times10^{{{ex}}}$")
for t, n in [("pq-uniform", "uni"), ("pq-uniform-hide", "hide")]:
    a = adv[t]
    put(f"p{n.capitalize()}", f"{a['obfs4_pass_prob_per_conn_both']:.3f}")
    put(f"{n}NeedTwo", str(a["connections_for_fpr_1e-2"])); put(f"{n}NeedThree", str(a["connections_for_fpr_1e-3"]))
    put(f"{n}NeedTwoC", str(a["connections_for_fpr_1e-2_client_only"]))
    put(f"{n}NeedThreeC", str(a["connections_for_fpr_1e-3_client_only"]))
    put(f"auc{n.capitalize()}", f"{a['auc_1conn']:.2f}")

# -------------------------------------------------------------- performance
bench = {}
for line in open(f"{PQM}/radix_bench.txt"):
    m = re.match(r"Benchmark(\w+)-\d+\s+\d+\s+(\d+) ns/op", line)
    if m:
        bench.setdefault(m.group(1), []).append(int(m.group(2)) / 1000)
med = {k: stx.median(v) for k, v in bench.items()}
put("encBig", f"{med['RadixEncodeBig']:.0f}"); put("encFixed", f"{med['RadixEncodeFixed']:.1f}")
put("decBig", f"{med['RadixDecodeBig']:.0f}"); put("decFixed", f"{med['RadixDecodeFixed']:.0f}")
put("encodeSpeedup", f"{med['RadixEncodeBig'] / med['RadixEncodeFixed']:.0f}")
put("decodeSpeedup", f"{med['RadixDecodeBig'] / med['RadixDecodeFixed']:.1f}")

P = {w: json.load(open(f"{PQM}/{w}/primitives.json")) for w in ["before", "after", "final"]}
H = {w: json.load(open(f"{PQM}/{w}/handshake_inprocess.json")) for w in ["before", "after", "final"]}
WN = {"before": "Big", "after": "Fixed", "final": "Final"}
for w, n in WN.items():
    put(f"ekDec{n}", f"{P[w]['kemeleon_DecodeEK']['mean_us']:.0f}")
    put(f"ctDec{n}", f"{P[w]['kemeleon_DecodeCiphertext']['mean_us']:.0f}")
    put(f"encap{n}", f"{P[w]['kemeleon_EncapsulateEncoded_total']['mean_us']:.0f}")
    put(f"keygen{n}", f"{P[w]['kemeleon_GenerateKeyPair_total']['mean_us']:.0f}")
    put(f"hs{n}Client", f"{H[w]['pq_client_cpu']['mean_us'] / 1000:.2f}")
    put(f"hs{n}Bridge", f"{H[w]['pq_server_cpu']['mean_us'] / 1000:.2f}")
    # client + bridge, summed from the rounded values shown in the table
    put(f"hs{n}Total", f"{round(H[w]['pq_client_cpu']['mean_us'] / 1000, 2) + round(H[w]['pq_server_cpu']['mean_us'] / 1000, 2):.2f}")
put("hsObfsClient", f"{H['final']['classical_client_cpu']['mean_us'] / 1000:.2f}")
put("hsObfsBridge", f"{H['final']['classical_server_cpu']['mean_us'] / 1000:.2f}")
put("hsObfsTotal", f"{round(H['final']['classical_client_cpu']['mean_us'] / 1000, 2) + round(H['final']['classical_server_cpu']['mean_us'] / 1000, 2):.2f}")
put("bridgeSpeedup", f"{H['before']['pq_server_cpu']['mean_us'] / H['final']['pq_server_cpu']['mean_us']:.1f}")
vz = json.load(open(f"{PQM}/vzeroupper.json"))
put("hmacAfterDecapsSlow", f"{vz['hmac_after_decaps_without_us']:.0f}")
VZ = json.load(open(f"{PQM}/vzeroupper.json"))
put("avxFactor", f"{VZ['hmac_after_decaps_without_us'] / VZ['hmac_baseline_us']:.0f}")
put("hmacAfterDecapsFast", f"{vz['hmac_after_decaps_with_us']:.1f}")
put("hmacBaseline", f"{vz['hmac_baseline_us']:.1f}")

# ---------------------------------------------------------------- latency
lat = {l: json.load(open(f"{PQM}/conn_latency_{l}.json")) for l in ["rtt0", "rtt50", "rtt150", "rtt300"]}
TN = {"obfs4": "Obfs", "pq-fixed": "Fix", "pq-uniform": "Uni", "pq-uniform-hide": "Hide"}
LN = {"rtt0": "Zero", "rtt50": "Fifty", "rtt150": "OneFifty", "rtt300": "ThreeHundred"}
medians = {}
for l, ln in LN.items():
    for t, tn in TN.items():
        v = np.array([s["handshake_us"] for s in lat[l][t]]) / 1000
        medians[(l, t)] = float(np.median(v))
        d = 2 if l == "rtt0" else 1
        put(f"lat{tn}{ln}", f"{np.median(v):.{d}f}"); put(f"lat{tn}{ln}P", f"{np.percentile(v, 95):.{d}f}")
    put(f"latN{ln}", str(len(lat[l]["obfs4"])))
    pq = max(medians[(l, t)] for t in ["pq-fixed", "pq-uniform", "pq-uniform-hide"])
    pqmin = min(medians[(l, t)] for t in ["pq-fixed", "pq-uniform", "pq-uniform-hide"])
    delta = pq - medians[(l, "obfs4")]
    put(f"latDelta{ln}", f"{delta:.2f}" if l == "rtt0" else f"{delta:.1f}")
    put(f"latDelta{ln}Min", f"{pqmin - medians[(l, 'obfs4')]:.2f}")
    put(f"latDelta{ln}Pct", f"{100 * delta / medians[(l, 'obfs4')]:.1f}")
z = lat["rtt0"]
put("parseArgsPq", f"{np.median([s['parse_args_us'] for s in z['pq-fixed']]) / 1000:.2f}")
put("parseArgsObfs", f"{np.median([s['parse_args_us'] for s in z['obfs4']]) / 1000:.2f}")
so = np.array([s["server_proc_us"] for s in z["obfs4"]]) / 1000
sp = np.array([s["server_proc_us"] for s in z["pq-fixed"]]) / 1000
put("srvObfsMed", f"{np.median(so):.2f}"); put("srvObfsSd", f"{so.std():.2f}")
put("srvPqMed", f"{np.median(sp):.2f}"); put("srvPqSd", f"{sp.std():.2f}")

thr = {}
for c, n in [(2, "Two"), (8, "Eight"), (32, "ThirtyTwo")]:
    reps = sorted(f for f in os.listdir(PQM) if re.fullmatch(rf"throughput_c{c}(_r\d+)?\.json", f))
    vals = [json.load(open(f"{PQM}/{f}")) for f in reps]
    o = stx.median(v["obfs4"] for v in vals); p = stx.median(v["pq-fixed"] for v in vals)
    put(f"thrObfs{n}", num(o)); put(f"thrPq{n}", num(p)); thr[c] = (o, p, len(vals))
put("thrReps", str(min(v[2] for v in thr.values())))

pr = json.load(open(f"{PQM}/active_probing.json"))
exp = {r["transport"]: r["expected_close_s"] for r in pr}
put("probeObfs", f"{exp['obfs4']:.0f}"); put("probePq", f"{exp['pq-fixed']:.0f}")
put("probeMaxDev", f"{1000 * max(abs(r['close_after_s'] - r['expected_close_s']) for r in pr):.0f}")
put("probeResp", str(max(r["response_bytes"] for r in pr)))
put("probeN", str(len(pr)))

N = json.load(open(f"{R}/nist.json"))
put("nistSeqs", str(N["encoded_keys"]["sequences"]))
names = {"frequency": "Frequency", "block_frequency": "Block freq.\\ ($M=128$)", "runs": "Runs",
         "longest_run": "Longest run ($M=10^4$)", "cumulative_sums": "Cumulative sums",
         "approximate_entropy": "Approx.\\ entropy ($m=10$)", "serial_1": "Serial $P_1$ ($m=16$)",
         "serial_2": "Serial $P_2$ ($m=16$)", "dft": "DFT"}
rows = []
for k, n in names.items():
    rows.append(f"{n} & {N['uniform_reference']['pass_proportion'][k]:.3f} & {N['encoded_keys']['pass_proportion'][k]:.3f} & "
                f"{N['encoded_ciphertexts']['pass_proportion'][k]:.3f} & {N['raw_keys_sanity']['pass_proportion'][k]:.2f} \\\\")
band = N["encoded_keys"]["band"]
table = (r"""\begin{table}[!htbp]
\caption{Nine of the SP 800-22 tests~\cite{sp80022} (the eight tests we implemented, with both statistics of the serial test): proportion of $10^6$-bit sequences with $p\geq0.01$. """
         + f"{N['encoded_keys']['sequences']} sequences per corpus (raw keys: {N['raw_keys_sanity']['sequences']}, as a sanity check); "
         + f"the suite's acceptance band is $\\geq{band:.3f}$." + r"""}\label{tab:nist}
\centering\footnotesize\setlength{\tabcolsep}{3.5pt}
\begin{tabular}{@{}lrrrr@{}}
\toprule
Test & \texttt{urandom} & \shortstack{Enc.\\keys} & \shortstack{Enc.\\ciphertexts} & \shortstack{Raw\\keys} \\
\midrule
""" + "\n".join(rows) + r"""
\bottomrule
\end{tabular}
\end{table}
""")
open(f"{MS}/nist_table.tex", "w").write(table)
put("nistAllPass", "yes" if N["encoded_keys"]["all_within_band"] and N["encoded_ciphertexts"]["all_within_band"] else "NO")


# ------------------------------------------------------- suites and DoS cost
ARM = os.environ.get("ARM_OUT", "/tmp/arm")
for host, d, pre in [("x86", PQM, ""), ("arm", ARM, "arm")]:
    J = json.load(open(f"{d}/junk_cost.json"))
    for k, n in [("obfs4_junk_us", "JunkObfs"), ("pq_rejection_junk_us", "JunkRej"),
                 ("pq_default_junk_us", "JunkDef"), ("pq_hybrid_junk_us", "JunkHyb"),
                 ("pq_rejection_2keys_junk_us", "JunkRejTwo"),
                 ("pq_rejection_honest_bridge_us", "HonRej"), ("pq_default_honest_bridge_us", "HonDef"),
                 ("pq_hybrid_honest_bridge_us", "HonHyb"), ("pq_rejection_2keys_honest_bridge_us", "HonRejTwo")]:
        put(f"{pre}{n}" if pre else n[0].lower() + n[1:], f"{J[k]:.0f}")
    hs = json.load(open(f"{d}/final/handshake_inprocess.json"))
    if pre:
        put("armHsPqBridge", f"{hs['pq_server_cpu']['p50_us'] / 1000:.2f}")
        put("armHsObfsBridge", f"{hs['classical_server_cpu']['p50_us'] / 1000:.2f}")
        put("armHsPqTotal", f"{hs['pq_total']['p50_us'] / 1000:.2f}")
        put("armHsObfsTotal", f"{hs['classical_total']['p50_us'] / 1000:.2f}")
J = json.load(open(f"{PQM}/junk_cost.json"))
put("junkRatio", f"{J['pq_rejection_junk_us'] / J['obfs4_junk_us']:.1f}")

ET = json.load(open(f"{PQM}/encap_timing.json"))
for k, n in [("rejection", "Rej"), ("default", "Def")]:
    for p, pn in [("p10", "Ten"), ("p50", "Med"), ("p90", "Ninety"), ("p99", "NinetyNine")]:
        put(f"encap{n}{pn}", f"{ET[k][p + '_us']:.0f}")
EA = json.load(open(f"{ARM}/encap_timing.json"))
for k, n in [("rejection", "Rej"), ("default", "Def")]:
    for p, pn in [("p10", "Ten"), ("p50", "Med"), ("p90", "Ninety"), ("p99", "NinetyNine")]:
        put(f"armEncap{n}{pn}", f"{EA[k][p + '_us']:.0f}")
    put(f"armEncap{n}Sd", f"{EA[k]['sd_us']:.0f}")

# ARM latency and throughput
al = json.load(open(f"{ARM}/conn_latency_rtt0.json"))
put("armLatObfs", f"{np.median([s['handshake_us'] for s in al['obfs4']]) / 1000:.2f}")
put("armLatUni", f"{np.median([s['handshake_us'] for s in al['pq-uniform']]) / 1000:.2f}")
put("armLatFix", f"{np.median([s['handshake_us'] for s in al['pq-fixed']]) / 1000:.2f}")
at = json.load(open(f"{ARM}/throughput_c32.json"))
put("armThrObfs", num(at["obfs4"])); put("armThrPq", num(at["pq-fixed"]))

# -------------------------------------------- trained classifier and timing
CS = json.load(open(f"{R}/censor_sim.json"))
put("csN", str(CS["n_per_config"]["obfs4"]))
put("delayObfs", f"{CS['median_bridge_delay_ms']['obfs4']:.2f}")
put("delayPqMin", f"{min(v for k, v in CS['median_bridge_delay_ms'].items() if k != 'obfs4'):.2f}")
put("delayPqMax", f"{max(v for k, v in CS['median_bridge_delay_ms'].items() if k != 'obfs4'):.2f}")
for t, n in [("pq-fixed", "Fix"), ("pq-uniform", "Uni"), ("pq-uniform-hide", "Hide")]:
    sc = CS["single_connection"][t]
    put(f"clfLen{n}", f"{sc['lengths_auc'][0]:.2f}")
    put(f"clfDelay{n}", f"{sc['delay_only_auc'][0]:.2f}")
    put(f"clfBoth{n}", f"{sc['lengths_and_delay_auc'][0]:.2f}")
    pb = CS["per_bridge"][t]
    for k, kn in [("1", "One"), ("2", "Two"), ("5", "Five"), ("10", "Ten"), ("20", "Twenty")]:
        put(f"pb{n}{kn}", f"{pb[k][0]:.2f}" if pb[k][0] < 0.995 else f"{pb[k][0]:.3f}")
T = CS["time_to_detection"]["pq-uniform"]
put("ttdUniOneFull", f"{T['rate1_sample1.0']['hours_fpr_1e-3']:.0f}")
put("ttdUniTenFull", f"{T['rate10_sample1.0']['hours_fpr_1e-3']:.1f}")
put("ttdUniOneTenth", f"{T['rate1_sample0.1']['hours_fpr_1e-3']:.0f}")
put("ttdUniHundredFull", f"{60 * T['rate100_sample1.0']['hours_fpr_1e-3']:.0f}")
FF = CS["obfs4_false_flags_per_1000_bridges"]
put("ffFive", f"{FF['5']:.0f}"); put("ffTen", f"{FF['10']:.1f}"); put("ffFourteen", f"{FF['14']:.1f}")

# ------------------------------------------------------------ parameter sets
P = json.load(open(f"{R}/paramsets.json"))
for ps, n in [("ML-KEM-512", "Five"), ("ML-KEM-768", "Seven"), ("ML-KEM-1024", "Ten")]:
    p = P[ps]
    put(f"ps{n}Range", f"{p['range_fpr_log10']:.0f}")
    put(f"ps{n}MfOne", pct(p["mf_detect_raw_1ct_exact"], 1) if p["mf_detect_raw_1ct_exact"] < 0.9995 else "100")
    put(f"ps{n}MfTwo", pct(p["mf_detect_raw_2ct_exact"], 1) if p["mf_detect_raw_2ct_exact"] < 0.9995 else "100")
    put(f"ps{n}Kl", f"{p['mf_kl_per_coeff']:.4f}")
    put(f"ps{n}AccEk", f"{p['ek_accept_exact']:.2f}"); put(f"ps{n}AccCt", f"{p['ct_accept']:.2f}")
    put(f"ps{n}EncEk", num(p["enc_ek_bytes"])); put(f"ps{n}EncCt", num(p["enc_ct_bytes"]))
    put(f"ps{n}Msb", pct(p["msb_detect_raw"], 1))
    put(f"ps{n}N", num(p["n"]))
    put(f"ps{n}EncMax", pct(max(p["range_detect_enc"], p["msb_detect_enc"], p["mf_detect_enc_1ct"]), 1))

# ------------------------------------------------------- fuzzing and vectors
FZ = os.environ.get("FUZZ_DIR", f"{PQM}/fuzz")
tot = 0
for f, n in [("FuzzRadixDecode", "Radix"), ("FuzzDecodeRoundTrip", "Round"),
             ("FuzzPQClientParse", "Client"), ("FuzzPQServerParse", "Server")]:
    ex = [int(x) for x in re.findall(r"execs: (\d+)", open(f"{FZ}/{f}.log").read())]
    assert "FAIL" not in open(f"{FZ}/{f}.log").read()
    put(f"fuzz{n}", num(ex[-1])); tot += ex[-1]
put("fuzzTotal", num(tot))
VEC = os.environ.get("VECTORS", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vectors", "kemeleon768_decode_vectors.json"))
V = json.load(open(VEC))["vectors"]
put("vecN", str(len(V)))
put("vecCtRej", str(sum(1 for v in V if v["kind"] == "ct" and v["encoding"] == "rejection")))
put("vecCtRejZero", str(sum(1 for v in V if v["kind"] == "ct" and v["encoding"] == "rejection"
                            and (bytes.fromhex(v["encoded"])[1123] & 0xFC) == 0)))

# ----------------------------------------------------------- private Tor
PT = os.environ.get("PRIVTOR", f"{PQM}/privatetor")
cfgs = sorted(f[:-len(".verify.log")] for f in os.listdir(PT) if f.endswith(".verify.log"))
ok = [c for c in cfgs if "Transmission: Success" in open(f"{PT}/{c}.verify.log").read()
      and "Bootstrapped 100%" in open(f"{PT}/{c}.bootstrap.log").read()]
put("torCfgs", str(len(cfgs))); put("torOk", str(len(ok)))

# ------------------------------------------------------- coordinated cover
DEF = json.load(open(f"{R}/defense.json"))
sc = DEF["single_connection"]
f3 = lambda x: f"{x:.3f}"
f2 = lambda x: f"{x:.3f}" if x >= 0.99 else f"{x:.2f}"
for key, tag in [("baseline", "Base"), ("jitter500", "JitA"), ("jitter1000", "JitB"), ("jitter2000", "JitC"),
                 ("light", "Light"), ("coordinated", "Coord"), ("coord_vs_legacy", "Legacy")]:
    put(f"def{tag}Len", f2(sc[key]["lengths_auc"][0]))
    put(f"def{tag}Delay", f2(sc[key]["delay_only_auc"][0]))
    put(f"def{tag}Both", f2(sc[key]["lengths_and_delay_auc"][0]))
    put(f"def{tag}BothSd", f2(sc[key]["lengths_and_delay_auc"][1]))
PBR = json.load(open(f"{R}/defense_perbridge.json"))
for key, tag in [("baseline", "Base"), ("light", "Light"), ("coordinated", "Coord")]:
    for k, kt in [("1", "One"), ("2", "Two"), ("5", "Five"), ("10", "Ten"), ("20", "Twenty")]:
        put(f"pb{tag}{kt}", f2(PBR["comparisons"][key][k]["mean"]))
    put(f"pb{tag}TwentySd", f2(PBR["comparisons"][key]["20"]["sd"]))
for k, kt in [("1", "One"), ("2", "Two"), ("5", "Five"), ("10", "Ten"), ("20", "Twenty")]:
    put(f"pbNull{kt}", f2(PBR["null_coordinated"][k]["mean"]))
put("pbNullTwentyHi", f2(PBR["null_coordinated"]["20"]["hi95"]))
put("pbSplits", str(PBR["splits"])); put("pbBridges", num(PBR["bridges_per_class"]))
put("pbConns", num(PBR["connections_per_class"])); put("pbHalf", num(PBR["connections_per_class"] // 2))
cvp = PBR["coordinated_vs_null_p"]
put("pbCoordMaxExcess", f2(max(PBR["comparisons"]["coordinated"][k]["mean"] - PBR["null_coordinated"][k]["mean"] for k in cvp)))
put("pbCoordMinP", f"{min(cvp.values()):.3f}")
ab = PBR["ablation_coordinated_k20"]
put("abDelay", f2(ab["delay"]["mean"])); put("abBridgeLen", f2(ab["bridge_length"]["mean"]))
put("abClientLen", f2(ab["client_length"]["mean"])); put("abSegs", f2(ab["segments"]["mean"]))
bl = PBR["bridge_length_mean"]
zs = [(m - bl["expected"]) / (bl["se_per_replicate"] / np.sqrt(len(bl["obfs4_coord"]))) for m in [np.mean(bl["obfs4_coord"])]]
put("blObfsCoordZ", f"{zs[0]:.1f}")
put("defReps", str(DEF["replicates"]))
put("defN", num(DEF["n_per_config_per_replicate"]["obfs4"]))
hsd = DEF["handshake_ms"]
for key, tag in [("obfs4", "Obfs"), ("pq-uniform", "Pq"), ("pq-jitter500", "JitA"), ("pq-jitter1000", "JitB"),
                 ("pq-jitter2000", "JitC"), ("obfs4-light", "ObfsLight"), ("pq-light", "PqLight"),
                 ("obfs4-coord", "ObfsCoord"), ("pq-coord", "PqCoord")]:
    put(f"hs{tag}Med", f"{hsd[key]['median']:.2f}")
dl = DEF["delay_ms"]
for key, tag in [("obfs4", "Obfs"), ("pq-uniform", "Pq"), ("obfs4-coord", "ObfsCoord"), ("pq-coord", "PqCoord")]:
    put(f"dl{tag}Med", f"{dl[key]['p50']:.2f}")
put("dlPqPNinetyNine", f"{dl['pq-uniform']['p99']:.2f}"); put("dlObfsPNinetyNine", f"{dl['obfs4']['p99']:.2f}")
put("ksCoordClient", f"{DEF['ks']['coordinated']['client']:.2f}"); put("ksCoordServer", f"{DEF['ks']['coordinated']['server']:.2f}")
put("floorExtraClient", num(DEF["obfs4_floor_extra_bytes"]["client"]))
put("floorExtraServer", num(DEF["obfs4_floor_extra_bytes"]["server"]))
put("floorExtraTotal", f"{(DEF['obfs4_floor_extra_bytes']['client'] + DEF['obfs4_floor_extra_bytes']['server']) / 1000:.1f}")

# ------------------------------------------- statistical validation (review)
ST = json.load(open(f"{R}/defense_stats.json"))
H = ST["holdout"]
for key, tag in [("baseline", "Base"), ("coordinated", "Coord"), ("light", "Light"), ("coord_vs_legacy", "Legacy"),
                 ("jitter500", "JitA"), ("jitter1000", "JitB"), ("jitter2000", "JitC")]:
    g = H[key]["gbt"]["both"]
    put(f"ho{tag}", f2(g["auc"])); put(f"ho{tag}Lo", f2(g["ci95"][0])); put(f"ho{tag}Hi", f2(g["ci95"][1]))
    put(f"ho{tag}Len", f2(H[key]["gbt"]["lengths"]["auc"])); put(f"ho{tag}Delay", f2(H[key]["gbt"]["delay"]["auc"]))
    for c, ct in [("logreg", "Lr"), ("rf", "Rf"), ("knn", "Knn")]:
        put(f"ho{tag}{ct}", f2(H[key][c]["both"]["auc"]))
    lp = ST["lopo"][key]["per_replicate"]
    put(f"lopo{tag}Min", f2(min(lp))); put(f"lopo{tag}Max", f2(max(lp)))
for key, tag in [("coordinated", "Coord"), ("light", "Light")]:
    cis = [v["ci90"] for c in H[key].values() for v in c.values()]
    put(f"eq{tag}Lo", f2(min(c[0] for c in cis))); put(f"eq{tag}Hi", f2(max(c[1] for c in cis)))
    put(f"eq{tag}All", "all" if all(v["equivalent"] for c in H[key].values() for v in c.values()) else "not all")
put("eqDelta", f2(ST["delta"]))
PH = ST["per_bridge_holdout"]
for key, tag in [("baseline", "Base"), ("coordinated", "Coord"), ("light", "Light"), ("null_coordinated", "Null")]:
    vals = [PH[key][k]["mean"] for k in ("1", "2", "5", "10", "20")]
    put(f"pbho{tag}Min", f2(min(vals))); put(f"pbho{tag}Max", f2(max(vals)))
    put(f"pbho{tag}Twenty", f2(PH[key]["20"]["mean"])); put(f"pbho{tag}Five", f2(PH[key]["5"]["mean"]))
for key, tag in [("baseline", "Base"), ("coordinated", "Coord"), ("light", "Light")]:
    for k, kt in [("1", "One"), ("2", "Two"), ("10", "Ten")]:
        put(f"pbho{tag}{kt}", f2(PH[key][k]["mean"]))
put("pbhoCoordHiMax", f2(max(PH["coordinated"][k]["hi95"] for k in ("1", "2", "5", "10", "20"))))

# --------------------------------------------------------------- robustness
RB = json.load(open(f"{R}/robust.json"))
J = RB["jitter"]
put("rbRuns", str(RB["runs"]))
for j, jt in [("0", "Zero"), ("500", "Half"), ("1000", "One"), ("2000", "Two")]:
    put(f"jit{jt}NoneDelay", f2(J[j]["none"]["single_delay"][0])); put(f"jit{jt}NoneBoth", f2(J[j]["none"]["single_both"][0]))
    put(f"jit{jt}CoordBoth", f2(J[j]["coordinated"]["single_both"][0]))
cpb = [J[j]["coordinated"]["pb20"]["mean"] for j in J]; npb = [J[j]["null_pb20"]["mean"] for j in J]
put("jitCoordPbMin", f2(min(cpb))); put("jitCoordPbMax", f2(max(cpb)))
put("jitNullPbMin", f2(min(npb))); put("jitNullPbMax", f2(max(npb)))
cs1 = [J[j]["coordinated"]["single_both"][0] for j in J]
put("jitCoordMin", f2(min(cs1))); put("jitCoordMax", f2(max(cs1)))
LD = RB["load"]
for L, lt in [("1", "One"), ("2", "Two"), ("4", "Four")]:
    e = LD[L]
    put(f"ld{lt}CoordBoth", f2(e["coordinated"]["single_both"][0])); put(f"ld{lt}CoordDelay", f2(e["coordinated"]["single_delay"][0]))
    put(f"ld{lt}CoordPb", f2(e["coordinated"]["pb20"]["mean"])); put(f"ld{lt}NullPb", f2(e["null_pb20"]["mean"]))
    put(f"ld{lt}ExObfs", pct(e["p_exceeds_2ms"]["obfs4"], 1)); put(f"ld{lt}ExPq", pct(e["p_exceeds_2ms"]["pq-uniform"], 1))
SLW = RB["slow"]
for T in ("2", "6"):
    e = SLW["T" + T]
    put(f"slT{'Two' if T == '2' else 'Six'}Single", f2(e["single_slow"][0]))
    for ph, pt_ in [("0.0", "Zero"), ("0.1", "Ten"), ("0.2", "Twenty"), ("0.5", "Fifty"), ("1.0", "All")]:
        put(f"slT{'Two' if T == '2' else 'Six'}{pt_}", f2(e["pb20_vs_phi"][ph]["mean"]))
    put(f"slT{'Two' if T == '2' else 'Six'}Null", f2(e["null_pb20"]["mean"]))
put("slPqSlowPNinetyNine", f"{SLW['delay_ms']['pq-coord-slow'][1]:.1f}")
put("slObfsSlowPNinetyNine", f"{SLW['delay_ms']['obfs4-coord-slow'][1]:.1f}")

# slow-host runs: handshake latency (dial to completed handshake), four runs pooled
RD = os.environ.get("ROBUST_DIR", "/tmp/pqm/robust")
_lat = {}
for r in (1, 2, 3, 4):
    for k, v in json.load(open(f"{RD}/conn_latency_slow_r{r}.json")).items():
        _lat.setdefault(k, []).extend(x["handshake_us"] for x in v)
for k, tg in [("obfs4-coord", "ObfsTwo"), ("pq-coord", "PqTwo"), ("obfs4-t6", "ObfsSix"), ("pq-t6", "PqSix"),
              ("obfs4-t6-slow", "ObfsSixSlow"), ("pq-t6-slow", "PqSixSlow")]:
    put(f"slLat{tg}", f"{np.median(_lat[k]) / 1000:.1f}")
_jk = json.load(open(f"{PQM}/junk_cost.json"))
# junk connections per second needed to keep two vCPUs busy with rejection work alone
put("floodRej", num(round(2e6 / _jk["pq_rejection_junk_us"], -3)))
put("floodHyb", num(round(2e6 / _jk["pq_hybrid_junk_us"], -3)))
put("floodRejGbps", f"{2e6 / _jk['pq_rejection_junk_us'] * 8192 * 8 / 1e9:.1f}")  # at 8,192 bytes per junk connection
# ------------------------------------------------------------ extra stats
EX = json.load(open(f"{R}/extra_stats.json"))
ef = EX["effect"]
put("efMsbEnc", f"{ef['msb_enc'][0]:.2f}"); put("efMsbLo", f"{ef['msb_enc'][1]:.2f}"); put("efMsbHi", f"{ef['msb_enc'][2]:.2f}")
put("efKfEnc", f"{ef['k4_enc'][0]:.2f}"); put("efKfLo", f"{ef['k4_enc'][1]:.2f}"); put("efKfHi", f"{ef['k4_enc'][2]:.2f}")
put("efKfNull", f"{ef['k4_null']:.2f}"); put("efMsbRaw", f"{ef['msb_raw'][0]:.1f}"); put("efKfRaw", f"{ef['k4_raw'][0]:.1f}")
sb = EX["six_bits"]
put("sixMinP", f2(min(v for impl in sb.values() for kk, v in impl.items() if kk.endswith("_p"))))
AD = EX["adoption"]["by_share"]
for sh, tg in [("0", "Zero"), ("0.5", "Half"), ("0.9", "Ninety"), ("0.99", "NinetyNine")]:
    put(f"ad{tg}Two", num(AD[sh]["n_1e-2"])); put(f"ad{tg}Three", num(AD[sh]["n_1e-3"])); put(f"ad{tg}Fpr", f"{AD[sh]['fpr_k20']:.3f}")
put("adPClientOld", f"{EX['adoption']['p_client_old']:.3f}")
AC = EX["acceptance"]
put("accCtDerived", f"{AC['ct_derived']:.3f}"); put("accCtFactor", f"{AC['c2_factor']:.3f}"); put("accKeyDerived", f"{AC['key']:.3f}")
import math as _m
for n, tg in [(512, "Five"), (768, "Seven"), (1024, "Ten")]:
    l = n * _m.log10(3329 / 4096); e = _m.floor(l); mant = 10 ** (l - e)
    put(f"rangeExact{tg}", f"{mant:.1f}\\times10^{{{e}}}")
put("mfTwoCrit", "440")

# ------------------------------------------------------------------ Drivel
DR = json.load(open(f"{R}/drivel.json"))
for v, vt in [("as_shipped", ""), ("byte_aligned_t", "Fix")]:
    for name, tag in [("ML-KEM-768", "Seven"), ("ML-KEM-1024", "Ten")]:
        d = DR[v][name]
        put(f"dr{vt}{tag}T", str(d["t"]))
        put(f"dr{vt}{tag}Zero", num(d["top_bits_zero"]))
        put(f"dr{vt}{tag}N", num(d["n"]))
        put(f"dr{vt}{tag}FirstMax", str(d["first_byte_max"]))
        put(f"dr{vt}{tag}Unused", str(d["unused_top_bits"]))
        put(f"dr{vt}{tag}Bits", num(d["bits_b_plus_t"]))
        put(f"dr{vt}{tag}Len", num(d["encoded_bytes"]))
_m, _e = f"{DR['as_shipped']['ML-KEM-1024']['p_byte_chi2_all']:.0e}".split("e-")
put("drTenPAll", _m + r"\times 10^{-" + str(int(_e)) + "}")
put("drFixMinP", f2(min(DR["byte_aligned_t"][n][t] for n in DR["byte_aligned_t"] for t in ("p_first_byte", "p_middle_byte", "p_last_byte", "p_byte_chi2_all"))))
LP = DR["length_policy_ML-KEM-768"]
put("drCliLo", num(LP["client_first_flight_range"][0])); put("drCliHi", num(LP["client_first_flight_range"][1]))
put("drSrvLo", num(LP["server_first_flight_range"][0]))
put("drCliMean", num(LP["client_mean"])); put("drSrvMean", num(LP["server_mean"]))
put("drCliAbove", pct(LP["p_client_above_obfs4_max"], 0)); put("drSrvAbove", pct(LP["p_server_above_obfs4_max"], 0))

with open(f"{MS}/results.tex", "w") as f:
    f.write("% Generated by analysis/make_macros.py -- do not edit by hand.\n")
    for k in sorted(M):
        f.write(f"\\newcommand{{\\{k}}}{{{M[k]}}}\n")
print(f"{len(M)} macros written")
for k in sorted(M):
    print(f"{k:24s} {M[k]}")
