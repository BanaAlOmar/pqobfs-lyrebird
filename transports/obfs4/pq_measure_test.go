//go:build pqobfs && measure

// Measurement harness for the pq-obfs paper. Run with:
//
//	go test -tags "pqobfs measure" -run TestPQMeasure -v -count=1 ./transports/obfs4/
//
// Writes JSON/CSV results to $PQ_MEASURE_DIR (default /tmp/pqmeasure).

package obfs4

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

type stats struct {
	N      int     `json:"n"`
	MeanUs float64 `json:"mean_us"`
	SdUs   float64 `json:"sd_us"`
	MinUs  float64 `json:"min_us"`
	P50Us  float64 `json:"p50_us"`
	P90Us  float64 `json:"p90_us"`
	P95Us  float64 `json:"p95_us"`
	P99Us  float64 `json:"p99_us"`
	MaxUs  float64 `json:"max_us"`
}

func summarize(d []time.Duration) stats {
	xs := make([]float64, len(d))
	for i, v := range d {
		xs[i] = float64(v.Nanoseconds()) / 1000.0
	}
	sort.Float64s(xs)
	var sum, sq float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	for _, x := range xs {
		sq += (x - mean) * (x - mean)
	}
	q := func(p float64) float64 { return xs[int(math.Min(float64(len(xs)-1), math.Floor(p*float64(len(xs)))))] }
	return stats{len(xs), mean, math.Sqrt(sq / float64(len(xs))), xs[0], q(0.5), q(0.9), q(0.95), q(0.99), xs[len(xs)-1]}
}

func outDir() string {
	d := os.Getenv("PQ_MEASURE_DIR")
	if d == "" {
		d = "/tmp/pqmeasure"
	}
	os.MkdirAll(d, 0o755)
	return d
}

func writeJSON(t *testing.T, name string, v interface{}) {
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir(), name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// A. Primitive costs and rejection-sampling statistics
// ---------------------------------------------------------------------------

func TestPQMeasurePrimitives(t *testing.T) {
	const N = 5000
	res := map[string]interface{}{}

	// ML-KEM-768 key generation attempts until Kemeleon accepts (rejection loop).
	var kgenTotal, kgenAttempt, encapT, decapT, decodeT, padT, encodeT []time.Duration
	attemptHist := map[int]int{}
	accepted, tried := 0, 0
	for i := 0; i < N; i++ {
		attempts := 0
		start := time.Now()
		var raw []byte
		for {
			a0 := time.Now()
			pk, _, err := mlkem768.GenerateKeyPair(nil)
			if err != nil {
				t.Fatal(err)
			}
			raw = make([]byte, mlkem768.PublicKeySize)
			pk.Pack(raw)
			ok := mlkem_kemeleon.ProbeEncodeAccepts(raw)
			kgenAttempt = append(kgenAttempt, time.Since(a0))
			attempts++
			tried++
			if ok {
				accepted++
				break
			}
		}
		kgenTotal = append(kgenTotal, time.Since(start))
		attemptHist[attempts]++

		// Encode cost alone (accepted key).
		e0 := time.Now()
		kp, err := mlkem_kemeleon.GenerateKeyPair(nil) // includes its own loop; timed separately below
		_ = kp
		_ = e0
		if err != nil {
			t.Fatal(err)
		}

		// Encapsulate / decapsulate / decode / pad.
		c0 := time.Now()
		ct, ss1, err := mlkem_kemeleon.Encapsulate(kp.RawEncapsulationKey())
		encapT = append(encapT, time.Since(c0))
		if err != nil {
			t.Fatal(err)
		}
		d0 := time.Now()
		ss2, err := kp.Decapsulate(ct)
		decapT = append(decapT, time.Since(d0))
		if err != nil || string(ss1) != string(ss2) {
			t.Fatal("decap mismatch")
		}
		rep := kp.Representative()
		k0 := time.Now()
		if _, err := mlkem_kemeleon.DecodeEK(rep); err != nil {
			t.Fatal(err)
		}
		decodeT = append(decodeT, time.Since(k0))
		p0 := time.Now()
		if _, err := mlkem_kemeleon.NormalizePadding(make([]byte, 1188)); err != nil {
			t.Fatal(err)
		}
		padT = append(padT, time.Since(p0))
	}
	// Encode cost: time GenerateKeyPair (loop + encode) minus nothing; report directly.
	for i := 0; i < N; i++ {
		e0 := time.Now()
		if _, err := mlkem_kemeleon.GenerateKeyPair(nil); err != nil {
			t.Fatal(err)
		}
		encodeT = append(encodeT, time.Since(e0))
	}

	// Classical baseline: X25519 keypair with Elligator 2 rejection loop, and
	// a single X25519 keypair without Elligator.
	var ell2T, x25519T []time.Duration
	for i := 0; i < N; i++ {
		s0 := time.Now()
		if _, err := ntor.NewKeypair(true); err != nil {
			t.Fatal(err)
		}
		ell2T = append(ell2T, time.Since(s0))
		s1 := time.Now()
		if _, err := ntor.NewKeypair(false); err != nil {
			t.Fatal(err)
		}
		x25519T = append(x25519T, time.Since(s1))
	}

	res["mlkem768_keygen_single_attempt"] = summarize(kgenAttempt)
	res["mlkem768_keygen_until_accept"] = summarize(kgenTotal)
	res["kemeleon_GenerateKeyPair_total"] = summarize(encodeT)
	res["mlkem768_encapsulate"] = summarize(encapT)
	res["mlkem768_decapsulate"] = summarize(decapT)
	res["kemeleon_DecodeEK"] = summarize(decodeT)

	// Ciphertext encoding: full EncapsulateEncoded (with rejection loop),
	// DecodeCiphertext, and the single-attempt acceptance rate.
	var encapEncT, decodeCtT []time.Duration
	ctAccepted, ctTried := 0, 0
	kpFixed, _ := mlkem_kemeleon.GenerateKeyPair(nil)
	rawFixed := kpFixed.RawEncapsulationKey()
	for i := 0; i < N; i++ {
		e0 := time.Now()
		ec, err := mlkem_kemeleon.EncapsulateEncoded(rawFixed)
		encapEncT = append(encapEncT, time.Since(e0))
		if err != nil {
			t.Fatal(err)
		}
		d0 := time.Now()
		if _, err := mlkem_kemeleon.DecodeCiphertext(ec.Encoded); err != nil {
			t.Fatal(err)
		}
		decodeCtT = append(decodeCtT, time.Since(d0))
		ct, _, err := mlkem_kemeleon.Encapsulate(rawFixed)
		if err != nil {
			t.Fatal(err)
		}
		ctTried++
		if mlkem_kemeleon.ProbeEncodeCtAccepts(ct) {
			ctAccepted++
		}
	}
	res["kemeleon_EncapsulateEncoded_total"] = summarize(encapEncT)
	res["kemeleon_DecodeCiphertext"] = summarize(decodeCtT)
	res["ct_acceptance_rate"] = float64(ctAccepted) / float64(ctTried)
	res["NormalizePadding_1188_to_4096"] = summarize(padT)
	res["x25519_elligator2_keypair"] = summarize(ell2T)
	res["x25519_plain_keypair"] = summarize(x25519T)
	res["acceptance_rate"] = float64(accepted) / float64(tried)
	res["attempts_hist"] = attemptHist
	res["attempts_mean"] = float64(tried) / float64(N)
	writeJSON(t, "primitives.json", res)
	t.Logf("acceptance %.4f, mean attempts %.3f, hist %v", float64(accepted)/float64(tried), float64(tried)/float64(N), attemptHist)
}

// ---------------------------------------------------------------------------
// B. In-process handshake latency, classical vs pq
// ---------------------------------------------------------------------------

func TestPQMeasureHandshakeInProcess(t *testing.T) {
	const N = 2000
	nodeID, _ := ntor.NewNodeID(make([]byte, ntor.NodeIDLength))
	res := map[string]interface{}{}

	// Classical.
	idKP, _ := ntor.NewKeypair(false)
	filter, _ := replayfilter.New(20 * time.Minute)
	var cTotal, cClient, cServer []time.Duration
	for i := 0; i < N; i++ {
		t0 := time.Now()
		ckp, _ := ntor.NewKeypair(true)
		chs := newClientHandshake(nodeID, idKP.Public(), ckp)
		hello, err := chs.generateHandshake()
		if err != nil {
			t.Fatal(err)
		}
		c1 := time.Since(t0)
		s0 := time.Now()
		skp, _ := ntor.NewKeypair(true)
		shs := newServerHandshake(nodeID, idKP, skp)
		if _, err := shs.parseClientHandshake(filter, hello); err != nil {
			t.Fatal(err)
		}
		resp, err := shs.generateHandshake()
		if err != nil {
			t.Fatal(err)
		}
		sT := time.Since(s0)
		c2 := time.Now()
		if _, _, err := chs.parseServerHandshake(resp); err != nil {
			t.Fatal(err)
		}
		cT := c1 + time.Since(c2)
		cTotal = append(cTotal, time.Since(t0))
		cClient = append(cClient, cT)
		cServer = append(cServer, sT)
	}
	res["classical_total"] = summarize(cTotal)
	res["classical_client_cpu"] = summarize(cClient)
	res["classical_server_cpu"] = summarize(cServer)

	// pq-obfs.
	staticKP, _ := mlkem_kemeleon.GenerateKeyPair(nil)
	serverRawEK := staticKP.RawEncapsulationKey()
	filter2, _ := replayfilter.New(20 * time.Minute)
	var pTotal, pClient, pServer []time.Duration
	for i := 0; i < N; i++ {
		t0 := time.Now()
		chs, err := newPQClientHandshake(nodeID, serverRawEK)
		if err != nil {
			t.Fatal(err)
		}
		hello, err := chs.generateHandshake()
		if err != nil {
			t.Fatal(err)
		}
		c1 := time.Since(t0)
		s0 := time.Now()
		shs := newPQServerHandshake(nodeID, staticKP)
		if _, err := shs.parseClientHandshake(filter2, hello); err != nil {
			t.Fatal(err)
		}
		resp, err := shs.generateHandshake()
		if err != nil {
			t.Fatal(err)
		}
		sT := time.Since(s0)
		c2 := time.Now()
		if _, _, err := chs.parseServerHandshake(resp); err != nil {
			t.Fatal(err)
		}
		cT := c1 + time.Since(c2)
		pTotal = append(pTotal, time.Since(t0))
		pClient = append(pClient, cT)
		pServer = append(pServer, sT)
	}
	res["pq_total"] = summarize(pTotal)
	res["pq_client_cpu"] = summarize(pClient)
	res["pq_server_cpu"] = summarize(pServer)
	writeJSON(t, "handshake_inprocess.json", res)
}

// ---------------------------------------------------------------------------
// C. Handshake over a real TCP loopback connection (for packet capture)
// ---------------------------------------------------------------------------

func readClassical(conn net.Conn, parse func([]byte) (int, error)) ([]byte, error) {
	buf := make([]byte, 0, maxHandshakeLength)
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if _, perr := parse(buf); perr == nil {
				return buf, nil
			} else if perr != ErrMarkNotFoundYet {
				return nil, perr
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

func TestPQMeasureHandshakeTCP(t *testing.T) {
	const N = 500
	nodeID, _ := ntor.NewNodeID(make([]byte, ntor.NodeIDLength))
	res := map[string]interface{}{}

	// --- classical over TCP (port 41100) ---
	idKP, _ := ntor.NewKeypair(false)
	filter, _ := replayfilter.New(20 * time.Minute)
	ln, err := net.Listen("tcp", "127.0.0.1:41100")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				skp, _ := ntor.NewKeypair(true)
				shs := newServerHandshake(nodeID, idKP, skp)
				var seedErr error
				_, err := readClassical(c, func(b []byte) (int, error) {
					_, seedErr = shs.parseClientHandshake(filter, b)
					return 0, seedErr
				})
				if err != nil {
					return
				}
				resp, _ := shs.generateHandshake()
				c.Write(resp)
			}(c)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	var cDial, cHS []time.Duration
	var cLens []int
	for i := 0; i < N; i++ {
		t0 := time.Now()
		conn, err := net.Dial("tcp", "127.0.0.1:41100")
		if err != nil {
			t.Fatal(err)
		}
		dialT := time.Since(t0)
		h0 := time.Now()
		ckp, _ := ntor.NewKeypair(true)
		chs := newClientHandshake(nodeID, idKP.Public(), ckp)
		hello, _ := chs.generateHandshake()
		cLens = append(cLens, len(hello))
		if _, err := conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		if _, err := readClassical(conn, func(b []byte) (int, error) {
			_, _, e := chs.parseServerHandshake(b)
			return 0, e
		}); err != nil {
			t.Fatal(err)
		}
		cHS = append(cHS, time.Since(h0))
		cDial = append(cDial, dialT)
		conn.Close()
	}
	ln.Close()
	res["classical_tcp_dial"] = summarize(cDial)
	res["classical_tcp_handshake_after_connect"] = summarize(cHS)
	res["classical_client_hello_lengths_sample"] = cLens[:20]

	// --- pq over TCP (port 41200) ---
	staticKP, _ := mlkem_kemeleon.GenerateKeyPair(nil)
	serverRawEK := staticKP.RawEncapsulationKey()
	filter2, _ := replayfilter.New(20 * time.Minute)
	ln2, err := net.Listen("tcp", "127.0.0.1:41200")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				shs := newPQServerHandshake(nodeID, staticKP)
				buf := make([]byte, pqHandshakeLength)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				if _, err := shs.parseClientHandshake(filter2, buf); err != nil {
					return
				}
				resp, _ := shs.generateHandshake()
				c.Write(resp)
			}(c)
		}
	}()
	time.Sleep(100 * time.Millisecond)
	var pDial, pHS []time.Duration
	for i := 0; i < N; i++ {
		t0 := time.Now()
		conn, err := net.Dial("tcp", "127.0.0.1:41200")
		if err != nil {
			t.Fatal(err)
		}
		dialT := time.Since(t0)
		h0 := time.Now()
		chs, _ := newPQClientHandshake(nodeID, serverRawEK)
		hello, _ := chs.generateHandshake()
		if len(hello) != pqHandshakeLength {
			t.Fatalf("hello len %d", len(hello))
		}
		if _, err := conn.Write(hello); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, pqHandshakeLength)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if _, _, err := chs.parseServerHandshake(buf); err != nil {
			t.Fatal(err)
		}
		pHS = append(pHS, time.Since(h0))
		pDial = append(pDial, dialT)
		conn.Close()
	}
	ln2.Close()
	res["pq_tcp_dial"] = summarize(pDial)
	res["pq_tcp_handshake_after_connect"] = summarize(pHS)
	writeJSON(t, "handshake_tcp.json", res)
}

// ---------------------------------------------------------------------------
// D. Byte statistics of raw vs Kemeleon-encoded keys (figure data)
// ---------------------------------------------------------------------------

func TestPQMeasureByteStats(t *testing.T) {
	const N = 1000
	rawPop := make([]int, 9)
	encPop := make([]int, 9)
	msbRaw, msbEnc := make([]int, 0, N), make([]int, 0, N)
	chiRaw, chiEnc := make([]float64, 0, N), make([]float64, 0, N)
	topByteRaw := map[int]int{}
	topByteEnc := map[int]int{}
	chi2 := func(b []byte) float64 {
		var h [256]int
		for _, v := range b {
			h[v]++
		}
		e := float64(len(b)) / 256.0
		var s float64
		for _, c := range h {
			s += (float64(c) - e) * (float64(c) - e) / e
		}
		return s
	}
	msbCount := func(coeffBlock []byte) int {
		n := 0
		for i := 0; i+2 < len(coeffBlock); i += 3 {
			b0, b1, b2 := coeffBlock[i], coeffBlock[i+1], coeffBlock[i+2]
			c0 := uint16(b0) | uint16(b1&0x0F)<<8
			c1 := uint16(b1>>4) | uint16(b2)<<4
			if c0 >= 2048 {
				n++
			}
			if c1 >= 2048 {
				n++
			}
		}
		return n
	}
	for i := 0; i < N; i++ {
		kp, err := mlkem_kemeleon.GenerateKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		raw := kp.RawEncapsulationKey()
		enc := kp.Representative()
		for _, b := range raw {
			rawPop[bits.OnesCount8(b)]++
		}
		for _, b := range enc {
			encPop[bits.OnesCount8(b)]++
		}
		msbRaw = append(msbRaw, msbCount(raw[:1152]))
		msbEnc = append(msbEnc, msbCount(enc[:1152]))
		chiRaw = append(chiRaw, chi2(raw))
		chiEnc = append(chiEnc, chi2(enc))
		topByteRaw[int(raw[1151]>>2)]++
		topByteEnc[int(enc[1123]>>2)]++
	}
	det := func(counts []int) (int, float64) {
		d := 0
		var sum float64
		for _, m := range counts {
			z := (float64(m) - 384) / math.Sqrt(768*0.25)
			p := 2 * 0.5 * math.Erfc(math.Abs(z)/math.Sqrt2)
			if p < 0.001 {
				d++
			}
			sum += float64(m)
		}
		return d, sum / float64(len(counts))
	}
	detChi := func(xs []float64) int {
		d := 0
		for _, x := range xs {
			if x > 330.5 {
				d++
			}
		}
		return d
	}
	dr, mr := det(msbRaw)
	de, me := det(msbEnc)
	res := map[string]interface{}{
		"n":                     N,
		"popcount_hist_raw":     rawPop,
		"popcount_hist_encoded": encPop,
		"msb_detect_raw":        dr,
		"msb_detect_encoded":    de,
		"msb_mean_raw":          mr,
		"msb_mean_encoded":      me,
		"chi2_detect_raw":       detChi(chiRaw),
		"chi2_detect_encoded":   detChi(chiEnc),
		"top6bits_hist_encoded": topByteEnc,
	}
	writeJSON(t, "bytestats.json", res)
	fmt.Printf("MSB raw %d/%d enc %d/%d; chi2 raw %d enc %d; mean msb raw %.1f enc %.1f\n", dr, N, de, N, detChi(chiRaw), detChi(chiEnc), mr, me)
}

// ---------------------------------------------------------------------------
// E. Ciphertext uniformity: matched-filter detector on raw vs encoded c_1
// ---------------------------------------------------------------------------

func TestPQMeasureCiphertextStats(t *testing.T) {
	const n = 1000
	kp, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	rawEK := kp.RawEncapsulationKey()

	// Per-coefficient log-likelihood ratio under Compress_10.
	counts := make([]int, 1<<mlkem_kemeleon.DU)
	for x := 0; x < mlkem_kemeleon.Q; x++ {
		counts[mlkem_kemeleon.CompressForTest(uint32(x), mlkem_kemeleon.DU)]++
	}
	llr := make([]float64, len(counts))
	for v, c := range counts {
		llr[v] = math.Log(float64(c) / float64(mlkem_kemeleon.Q) * float64(int(1)<<mlkem_kemeleon.DU))
	}
	score := func(b []byte) float64 {
		vals := mlkem_kemeleon.UnpackBitsForTest(b, mlkem_kemeleon.DU, mlkem_kemeleon.CoeffLen)
		var s float64
		for _, v := range vals {
			s += llr[v]
		}
		return s
	}
	mean := func(xs []float64) float64 {
		var s float64
		for _, x := range xs {
			s += x
		}
		return s / float64(len(xs))
	}
	sd := func(xs []float64, m float64) float64 {
		var v float64
		for _, x := range xs {
			v += (x - m) * (x - m)
		}
		return math.Sqrt(v / float64(len(xs)))
	}

	buf := make([]byte, mlkem_kemeleon.C1Bytes)
	var nullS []float64
	for i := 0; i < 5000; i++ {
		mlkem_kemeleon.RandForTest(buf)
		nullS = append(nullS, score(buf))
	}
	m0 := mean(nullS)
	s0 := sd(nullS, m0)
	thr := m0 + 3.09*s0 // one-sided alpha = 0.001

	var rawS, encS []float64
	rawDet, encDet := 0, 0
	for i := 0; i < n; i++ {
		ec, err := mlkem_kemeleon.EncapsulateEncoded(rawEK)
		if err != nil {
			t.Fatal(err)
		}
		r := score(ec.Raw[:mlkem_kemeleon.C1Bytes])
		e := score(ec.Encoded[:mlkem_kemeleon.C1Bytes])
		rawS = append(rawS, r)
		encS = append(encS, e)
		if r > thr {
			rawDet++
		}
		if e > thr {
			encDet++
		}
	}
	mr, me := mean(rawS), mean(encS)
	res := map[string]interface{}{
		"n":                     n,
		"null_mean":             m0,
		"null_sd":               s0,
		"threshold_alpha_0.001": thr,
		"raw_mean":              mr,
		"raw_sd":                sd(rawS, mr),
		"encoded_mean":          me,
		"encoded_sd":            sd(encS, me),
		"raw_detected":          rawDet,
		"encoded_detected":      encDet,
		"raw_sigma_separation":  (mr - m0) / s0,
	}
	writeJSON(t, "ciphertext_stats.json", res)
	fmt.Printf("CT matched filter: raw %d/%d (%.1f%%, %.2f sigma), encoded %d/%d (%.1f%%)\n",
		rawDet, n, 100*float64(rawDet)/n, (mr-m0)/s0, encDet, n, 100*float64(encDet)/n)
}
