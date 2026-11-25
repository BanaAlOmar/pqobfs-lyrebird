package mlkem_kemeleon

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

// bigEncode is the original math/big accumulator (the implementation the
// paper's first measurements used), kept as the differential-testing oracle.
func bigEncode(coeffs []uint16) []byte {
	r := new(big.Int)
	qBig := big.NewInt(Q)
	qPow := big.NewInt(1)
	term := new(big.Int)
	for i := 0; i < CoeffLen; i++ {
		term.SetUint64(uint64(coeffs[i]))
		term.Mul(term, qPow)
		r.Add(r, term)
		qPow.Mul(qPow, qBig)
	}
	out := make([]byte, ThatLen)
	rb := r.Bytes()
	for i, bv := range rb {
		out[len(rb)-1-i] = bv
	}
	return out
}

// bigDecode is the original math/big digit extraction.
func bigDecode(src []byte) ([]uint16, bool) {
	be := make([]byte, ThatLen)
	for i := 0; i < ThatLen; i++ {
		be[ThatLen-1-i] = src[i]
	}
	r := new(big.Int).SetBytes(be)
	qBig := big.NewInt(Q)
	rem := new(big.Int)
	out := make([]uint16, CoeffLen)
	for i := 0; i < CoeffLen; i++ {
		r.DivMod(r, qBig, rem)
		out[i] = uint16(rem.Uint64())
	}
	return out, r.Sign() == 0
}

func randCoeffs(t testing.TB) []uint16 {
	c := make([]uint16, CoeffLen)
	var b [2]byte
	for i := range c {
		for {
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			v := uint16(b[0]) | uint16(b[1]&0x0F)<<8
			if v < Q {
				c[i] = v
				break
			}
		}
	}
	return c
}

func TestRadixMatchesBig(t *testing.T) {
	cases := [][]uint16{make([]uint16, CoeffLen)} // all zero
	allMax := make([]uint16, CoeffLen)
	for i := range allMax {
		allMax[i] = Q - 1
	}
	cases = append(cases, allMax)
	for i := 0; i < 2000; i++ {
		cases = append(cases, randCoeffs(t))
	}
	// Sparse high digits only, low digits only.
	hi := make([]uint16, CoeffLen)
	hi[CoeffLen-1] = Q - 1
	lo := make([]uint16, CoeffLen)
	lo[0] = 1
	cases = append(cases, hi, lo)

	for n, c := range cases {
		got := make([]byte, ThatLen)
		radixEncode(got, c)
		want := bigEncode(c)
		if !bytes.Equal(got, want) {
			t.Fatalf("case %d: encode mismatch", n)
		}
		dec := make([]uint16, CoeffLen)
		if !radixDecode(dec, got) {
			t.Fatalf("case %d: decode rejected a valid accumulator", n)
		}
		for i := range dec {
			if dec[i] != c[i] {
				t.Fatalf("case %d: digit %d = %d, want %d", n, i, dec[i], c[i])
			}
		}
	}
}

func TestRadixDecodeMatchesBigOnArbitraryBytes(t *testing.T) {
	// Arbitrary accumulators, including values >= q^768 that must be
	// rejected, agree with the math/big oracle.
	for n := 0; n < 3000; n++ {
		src := make([]byte, ThatLen)
		if _, err := rand.Read(src); err != nil {
			t.Fatal(err)
		}
		switch n % 3 {
		case 0:
			src[ThatLen-1] &^= MSBByteMask // always a valid encoding
		case 1:
			src[ThatLen-1] |= 0x04 // >= 2^8986: valid iff below q^768
		}
		want, wantOK := bigDecode(src)
		got := make([]uint16, CoeffLen)
		gotOK := radixDecode(got, src)
		if gotOK != wantOK {
			t.Fatalf("case %d: ok=%v, oracle %v", n, gotOK, wantOK)
		}
		if !gotOK {
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("case %d: digit %d mismatch", n, i)
			}
		}
	}
}

func BenchmarkRadixEncodeFixed(b *testing.B) {
	c := randCoeffs(b)
	dst := make([]byte, ThatLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		radixEncode(dst, c)
	}
}

func BenchmarkRadixEncodeBig(b *testing.B) {
	c := randCoeffs(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = bigEncode(c)
	}
}

func BenchmarkRadixDecodeFixed(b *testing.B) {
	src := bigEncode(randCoeffs(b))
	dst := make([]uint16, CoeffLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		radixDecode(dst, src)
	}
}

func BenchmarkRadixDecodeBig(b *testing.B) {
	src := bigEncode(randCoeffs(b))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = bigDecode(src)
	}
}
