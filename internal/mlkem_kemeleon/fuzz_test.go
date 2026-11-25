package mlkem_kemeleon

import (
	"bytes"
	mrand "math/rand"
	"testing"
)

// FuzzRadixDecode: the fixed-width decoder agrees with the math/big oracle
// on arbitrary accumulators, including invalid ones, and never panics.
func FuzzRadixDecode(f *testing.F) {
	f.Add(make([]byte, ThatLen))
	f.Fuzz(func(t *testing.T, b []byte) {
		src := make([]byte, ThatLen)
		copy(src, b)
		want, wantOK := bigDecode(src)
		got := make([]uint16, CoeffLen)
		if ok := radixDecode(got, src); ok != wantOK {
			t.Fatalf("ok=%v oracle=%v", ok, wantOK)
		} else if ok {
			for i := range got {
				if got[i] != want[i] {
					t.Fatalf("digit %d", i)
				}
			}
		}
	})
}

// FuzzDecodeRoundTrip: whatever decodes re-encodes to a representative that
// decodes to the same raw object (rejection and default encodings). The
// fuzzer mutates a seed from which the inputs are generated, which keeps
// each execution fast despite the 2.4 kB inputs.
func FuzzDecodeRoundTrip(f *testing.F) {
	f.Add(int64(0), uint8(0))
	f.Fuzz(func(t *testing.T, seed int64, fill uint8) {
		r := mrand.New(mrand.NewSource(seed))
		ct := make([]byte, EncodedCtLen)
		ek := make([]byte, EncodedLen)
		r.Read(ct)
		r.Read(ek)
		switch fill % 4 { // also exercise extreme inputs
		case 1:
			for i := range ct {
				ct[i] = 0xFF
			}
		case 2:
			for i := range ek {
				ek[i] = 0
			}
		}
		if raw, err := DecodeCiphertext(ct); err == nil {
			enc, err := EncodeCtDefault(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := DecodeCtDefault(enc); err != nil || !bytes.Equal(back, raw) {
				t.Fatal("default CT round trip")
			}
		}
		if raw, err := DecodeEK(ek); err == nil {
			enc, err := EncodeEKDefault(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			if back, err := DecodeEKDefault(enc); err != nil || !bytes.Equal(back, raw) {
				t.Fatal("default EK round trip")
			}
		}
		dct := make([]byte, DefaultCtLen)
		r.Read(dct)
		if _, err := DecodeCtDefault(dct); err != nil {
			t.Fatal("default CT decode must be total")
		}
	})
}
