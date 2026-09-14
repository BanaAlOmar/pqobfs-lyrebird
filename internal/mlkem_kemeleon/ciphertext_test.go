package mlkem_kemeleon_test

import (
	"bytes"
	"math"
	"math/bits"
	"testing"

	mk "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

// TestCiphertextEncodeDecodeRoundTrip asserts the encoded ciphertext decodes
// back to the exact raw ciphertext, and that the shared secret still
// decapsulates.
func TestCiphertextEncodeDecodeRoundTrip(t *testing.T) {
	for i := 0; i < 200; i++ {
		kp, err := mk.GenerateKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		ec, err := mk.EncapsulateEncoded(kp.RawEncapsulationKey())
		if err != nil {
			t.Fatal(err)
		}
		if len(ec.Encoded) != mk.EncodedCtLen {
			t.Fatalf("encoded ciphertext length = %d, want %d", len(ec.Encoded), mk.EncodedCtLen)
		}
		raw, err := mk.DecodeCiphertext(ec.Encoded)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(raw, ec.Raw) {
			t.Fatal("decoded ciphertext differs from the original")
		}
		ss, err := kp.Decapsulate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ss, ec.SharedSecret) {
			t.Fatal("shared secret mismatch after encode/decode round trip")
		}
	}
}

// TestCiphertextAcceptanceRate checks the single-attempt acceptance rate is
// close to the 0.77 the draft reports for ML-KEM-768.
func TestCiphertextAcceptanceRate(t *testing.T) {
	const n = 2000
	kp, err := mk.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := kp.RawEncapsulationKey()
	accepted := 0
	for i := 0; i < n; i++ {
		ct, _, err := mk.Encapsulate(raw)
		if err != nil {
			t.Fatal(err)
		}
		if mk.ProbeEncodeCtAccepts(ct) {
			accepted++
		}
	}
	rate := float64(accepted) / n
	t.Logf("ciphertext acceptance rate: %.4f over %d attempts", rate, n)
	if rate < 0.72 || rate > 0.82 {
		t.Fatalf("acceptance rate %.4f outside the expected band around 0.77", rate)
	}
}

// TestCiphertextUniformity applies the two detectors of the paper to raw and
// encoded ciphertexts: a per-bit balance check and the log-likelihood-ratio
// (matched filter) test that exploits the Compress_10 preimage structure. The
// raw ciphertext must be detectable and the encoded one must not.
func TestCiphertextUniformity(t *testing.T) {
	const n = 400
	kp, err := mk.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	rawEK := kp.RawEncapsulationKey()

	// Per-coefficient log-likelihood ratio for Compress_10 output values.
	llr := make([]float64, 1<<mk.DU)
	counts := make([]int, 1<<mk.DU)
	for x := 0; x < mk.Q; x++ {
		counts[mk.CompressForTest(uint32(x), mk.DU)]++
	}
	for v, c := range counts {
		llr[v] = math.Log(float64(c) / float64(mk.Q) * float64(int(1)<<mk.DU))
	}
	score := func(c1 []byte) float64 {
		vals := mk.UnpackBitsForTest(c1, mk.DU, mk.CoeffLen)
		var s float64
		for _, v := range vals {
			s += llr[v]
		}
		return s
	}

	// Null distribution: uniform bytes.
	var nullScores []float64
	buf := make([]byte, mk.C1Bytes)
	for i := 0; i < 2000; i++ {
		mk.RandForTest(buf)
		nullScores = append(nullScores, score(buf))
	}
	mean, sd := meanSd(nullScores)
	thr := mean + 3.09*sd // one-sided alpha = 0.001

	rawDet, encDet, popFail := 0, 0, 0
	for i := 0; i < n; i++ {
		ec, err := mk.EncapsulateEncoded(rawEK)
		if err != nil {
			t.Fatal(err)
		}
		if score(ec.Raw[:mk.C1Bytes]) > thr {
			rawDet++
		}
		if score(ec.Encoded[:mk.C1Bytes]) > thr {
			encDet++
		}
		// popcount sanity on the encoded form
		ones := 0
		for _, b := range ec.Encoded {
			ones += bits.OnesCount8(b)
		}
		if mu := float64(ones) / float64(len(ec.Encoded)); mu < 3.7 || mu > 4.3 {
			popFail++
		}
	}
	t.Logf("matched-filter detection: raw %d/%d (%.1f%%), encoded %d/%d (%.1f%%); popcount outliers %d",
		rawDet, n, 100*float64(rawDet)/n, encDet, n, 100*float64(encDet)/n, popFail)
	if float64(rawDet)/n < 0.5 {
		t.Fatalf("raw ciphertext should be detectable, got %.2f", float64(rawDet)/n)
	}
	if float64(encDet)/n > 0.05 {
		t.Fatalf("encoded ciphertext should not be detectable, got %.2f", float64(encDet)/n)
	}
}

func meanSd(xs []float64) (float64, float64) {
	var s float64
	for _, x := range xs {
		s += x
	}
	m := s / float64(len(xs))
	var v float64
	for _, x := range xs {
		v += (x - m) * (x - m)
	}
	return m, math.Sqrt(v / float64(len(xs)))
}

// TestDecodeCiphertextAcceptsAnyString asserts the length check is enforced
// and that every well-formed-length string decodes. The latter is a property,
// not an accident: the accepted accumulator range [0, 2^8986) is a subset of
// [0, q^768), so a censor cannot use "does it decode" as a distinguisher, and
// a decoder never rejects a genuine representative.
func TestDecodeCiphertextAcceptsAnyString(t *testing.T) {
	if _, err := mk.DecodeCiphertext(make([]byte, 10)); err == nil {
		t.Fatal("expected a length error")
	}
	all := bytes.Repeat([]byte{0xff}, mk.EncodedCtLen)
	if _, err := mk.DecodeCiphertext(all); err != nil {
		t.Fatalf("all-ones string should decode: %v", err)
	}
	buf := make([]byte, mk.EncodedCtLen)
	for i := 0; i < 500; i++ {
		mk.RandForTest(buf)
		if _, err := mk.DecodeCiphertext(buf); err != nil {
			t.Fatalf("uniform random string failed to decode: %v", err)
		}
	}
}
