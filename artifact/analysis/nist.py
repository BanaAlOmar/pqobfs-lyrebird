#!/usr/bin/env python3
"""NIST SP 800-22 Rev. 1a core tests on Kemeleon representatives.

Implements eight tests of the suite (frequency, block frequency, runs,
longest run of ones, cumulative sums, approximate entropy, serial, DFT)
following the formulas of SP 800-22 Rev. 1a, Section 2. Sequences of
N_BITS bits are cut from the concatenated corpora. For each test the
proportion of sequences with p >= 0.01 is compared with the suite's band
0.99 - 3 sqrt(0.99 * 0.01 / m). Sanity checks: os.urandom must pass and raw
ML-KEM keys must fail.
"""
import json, math, os
import numpy as np
from scipy.special import erfc, gammaincc
from scipy.stats import norm

CORPUS = os.environ.get("CORPUS_DIR", "/tmp/corpus")
OUT = os.environ.get("RESULTS_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "results"))
N_BITS = 10 ** 6

def igamc(a, x):
    return float(gammaincc(a, x))

def frequency(b):
    n = len(b); s = abs(int(2 * b.sum()) - n) / math.sqrt(n)
    return float(erfc(s / math.sqrt(2)))

def block_frequency(b, M=128):
    N = len(b) // M
    pi = b[: N * M].reshape(N, M).mean(1)
    chi2 = 4 * M * ((pi - 0.5) ** 2).sum()
    return igamc(N / 2, chi2 / 2)

def runs(b):
    n = len(b); pi = b.mean()
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + int((b[1:] != b[:-1]).sum())
    return float(erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi))))

def longest_run(b):
    # n >= 750,000: M = 10^4, N = 75, classes <=10, 11, ..., 15, >=16.
    M, N = 10000, 75
    pis = [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]
    blocks = b[: M * N].reshape(N, M)
    v = np.zeros(7)
    for blk in blocks:
        d = np.diff(np.r_[0, blk.astype(np.int8), 0])
        starts, ends = np.where(d == 1)[0], np.where(d == -1)[0]
        L = int((ends - starts).max()) if len(starts) else 0
        v[min(max(L, 10), 16) - 10] += 1
    chi2 = (((v - N * np.array(pis)) ** 2) / (N * np.array(pis))).sum()
    return igamc(6 / 2, chi2 / 2)

def cusum(b):
    n = len(b); s = np.cumsum(2 * b.astype(np.int64) - 1); z = int(np.abs(s).max())
    sq = math.sqrt(n)
    k1 = np.arange(int((-n / z + 1) // 4), int((n / z - 1) // 4) + 1)
    k2 = np.arange(int((-n / z - 3) // 4), int((n / z - 1) // 4) + 1)
    t1 = (norm.cdf((4 * k1 + 1) * z / sq) - norm.cdf((4 * k1 - 1) * z / sq)).sum()
    t2 = (norm.cdf((4 * k2 + 3) * z / sq) - norm.cdf((4 * k2 + 1) * z / sq)).sum()
    return float(1 - t1 + t2)

def pattern_counts(b, m):
    n = len(b); ext = np.r_[b, b[: m - 1]].astype(np.int64)
    v = np.zeros(n, dtype=np.int64)
    for j in range(m):
        v = (v << 1) | ext[j: j + n]
    return np.bincount(v, minlength=1 << m)

def approximate_entropy(b, m=10):
    n = len(b)
    def phi(mm):
        c = pattern_counts(b, mm) / n
        c = c[c > 0]
        return float((c * np.log(c)).sum())
    apen = phi(m) - phi(m + 1)
    chi2 = 2 * n * (math.log(2) - apen)
    return igamc(2 ** (m - 1), chi2 / 2)

def serial(b, m=16):
    n = len(b)
    def psi2(mm):
        if mm <= 0:
            return 0.0
        c = pattern_counts(b, mm).astype(np.float64)
        return float((2 ** mm / n) * (c ** 2).sum() - n)
    p0, p1, p2 = psi2(m), psi2(m - 1), psi2(m - 2)
    d1, d2 = p0 - p1, p0 - 2 * p1 + p2
    return igamc(2 ** (m - 2), d1 / 2), igamc(2 ** (m - 3), d2 / 2)

def dft(b):
    n = len(b); x = 2 * b.astype(np.float64) - 1
    s = np.abs(np.fft.rfft(x))[: n // 2]
    T = math.sqrt(math.log(1 / 0.05) * n)
    n0 = 0.95 * n / 2; n1 = int((s < T).sum())
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / 4)
    return float(erfc(abs(d) / math.sqrt(2)))

TESTS = ["frequency", "block_frequency", "runs", "longest_run", "cumulative_sums",
         "approximate_entropy", "serial_1", "serial_2", "dft"]

def battery(b):
    s1, s2 = serial(b)
    return dict(zip(TESTS, [frequency(b), block_frequency(b), runs(b), longest_run(b), cusum(b),
                            approximate_entropy(b), s1, s2, dft(b)]))

def run(data, m):
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    m = min(m, len(bits) // N_BITS)
    ps = [battery(bits[i * N_BITS:(i + 1) * N_BITS]) for i in range(m)]
    return m, {t: sum(p[t] >= 0.01 for p in ps) / m for t in TESTS}

def main():
    m = int(os.environ.get("NIST_SEQS", "90"))
    ek = np.fromfile(os.path.join(CORPUS, "ek_enc_circl.bin"), np.uint8).tobytes()
    ct = np.fromfile(os.path.join(CORPUS, "ct_enc_circl.bin"), np.uint8).tobytes()
    raw = np.fromfile(os.path.join(CORPUS, "ek_raw_circl.bin"), np.uint8).tobytes()
    res = {"bits_per_sequence": N_BITS}
    for name, data, mm in [("uniform_reference", os.urandom(len(ek)), m),
                           ("encoded_keys", ek, m), ("encoded_ciphertexts", ct, m),
                           ("raw_keys_sanity", raw, 10)]:
        k, props = run(data, mm)
        band = 0.99 - 3 * math.sqrt(0.99 * 0.01 / k)
        res[name] = {"sequences": k, "band": band, "pass_proportion": props,
                     "all_within_band": all(v >= band for v in props.values())}
        print(name, k, {t: round(v, 3) for t, v in props.items()}, res[name]["all_within_band"], flush=True)
    json.dump(res, open(os.path.join(OUT, "nist.json"), "w"), indent=1)

if __name__ == "__main__":
    main()
