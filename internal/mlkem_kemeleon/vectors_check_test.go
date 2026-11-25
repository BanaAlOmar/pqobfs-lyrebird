package mlkem_kemeleon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// TestDecodeVectors decodes the committed vectors
// (artifact/vectors/kemeleon768_decode_vectors.json), including every value
// of the six unused accumulator bits.
func TestDecodeVectors(t *testing.T) {
	b, err := os.ReadFile("../../artifact/vectors/kemeleon768_decode_vectors.json")
	if err != nil {
		t.Skip("no vector file")
	}
	var f struct {
		Vectors []struct {
			Kind        string `json:"kind"`
			Encoding    string `json:"encoding"`
			Encoded     string `json:"encoded"`
			ExpectedRaw string `json:"expected_raw"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for i, v := range f.Vectors {
		enc, _ := hex.DecodeString(v.Encoded)
		var raw []byte
		switch v.Kind + "/" + v.Encoding {
		case "ek/rejection":
			raw, err = DecodeEK(enc)
		case "ct/rejection":
			raw, err = DecodeCiphertext(enc)
		case "ek/default":
			raw, err = DecodeEKDefault(enc)
		case "ct/default":
			raw, err = DecodeCtDefault(enc)
		}
		if err != nil || hex.EncodeToString(raw) != v.ExpectedRaw {
			t.Fatalf("vector %d (%s/%s) does not decode", i, v.Kind, v.Encoding)
		}
	}
	t.Logf("%d vectors decode", len(f.Vectors))
}
