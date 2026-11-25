package mlkem_kemeleon

import (
	"bytes"
	"testing"
)

func TestDefaultEncodingRoundTrip(t *testing.T) {
	for i := 0; i < 50; i++ {
		kp, err := GenerateKeyPairDefault(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(kp.Representative()) != DefaultEKLen {
			t.Fatalf("EK length %d", len(kp.Representative()))
		}
		raw, err := DecodeEKDefault(kp.Representative())
		if err != nil || !bytes.Equal(raw, kp.RawEncapsulationKey()) {
			t.Fatal("EK round trip failed")
		}
		ect, err := EncapsulateEncodedDefault(raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(ect.Encoded) != DefaultCtLen {
			t.Fatalf("CT length %d", len(ect.Encoded))
		}
		ct, err := DecodeCtDefault(ect.Encoded)
		if err != nil || !bytes.Equal(ct, ect.Raw) {
			t.Fatal("CT round trip failed")
		}
		ss, err := kp.Decapsulate(ct)
		if err != nil || !bytes.Equal(ss, ect.SharedSecret) {
			t.Fatal("shared secrets differ")
		}
	}
}

// Every byte string of the right length decodes (no invalid encodings), so
// decoding failures cannot be used as an oracle.
func TestDefaultDecodeTotal(t *testing.T) {
	for i := 0; i < 200; i++ {
		b := make([]byte, DefaultCtLen)
		RandForTest(b)
		if _, err := DecodeCtDefault(b); err != nil {
			t.Fatal(err)
		}
		e := make([]byte, DefaultEKLen)
		RandForTest(e)
		if _, err := DecodeEKDefault(e); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPreimages4(t *testing.T) {
	total := 0
	for v, s := range preimages4 {
		total += len(s)
		for _, x := range s {
			if compress(uint32(x), DV) != uint16(v) {
				t.Fatal("bad preimage")
			}
		}
	}
	if total != Q {
		t.Fatalf("preimage sets cover %d residues", total)
	}
}

func BenchmarkEncapsulateEncodedDefault(b *testing.B) {
	kp, _ := GenerateKeyPairDefault(nil)
	raw := kp.RawEncapsulationKey()
	for i := 0; i < b.N; i++ {
		_, _ = EncapsulateEncodedDefault(raw)
	}
}

func BenchmarkDecodeCtDefault(b *testing.B) {
	kp, _ := GenerateKeyPairDefault(nil)
	ect, _ := EncapsulateEncodedDefault(kp.RawEncapsulationKey())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeCtDefault(ect.Encoded)
	}
}
