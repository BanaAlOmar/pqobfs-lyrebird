//go:build vectors

package mlkem_kemeleon

// Decoding test vectors for ML-KEM-768 Kemeleon (rejection and default
// encodings). Encoders cannot be pinned by vectors -- their randomness is
// consumed in implementation-specific ways -- but decoders can. In
// particular every rejection-encoding vector comes in all 64 variants of the
// six unused accumulator bits, which a conforming decoder must clear
// (IntegerClearUnused) and decode to the same raw object.
//
//	go test -tags vectors -run TestWriteVectors ./internal/mlkem_kemeleon/
//
// Keys and encapsulations are derived deterministically from SHA-512 of a
// label and an index, so the raw objects are reproducible.

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

type vector struct {
	Kind        string `json:"kind"`     // "ek" or "ct"
	Encoding    string `json:"encoding"` // "rejection" or "default"
	Index       int    `json:"index"`
	UnusedBits  int    `json:"unused_bits,omitempty"` // value of the six bits, rejection only
	Encoded     string `json:"encoded"`
	ExpectedRaw string `json:"expected_raw"`
}

func detSeed(label string, i, n int) []byte {
	h := sha512.Sum512([]byte(fmt.Sprintf("pqobfs-kemeleon-vectors/%s/%d", label, i)))
	return h[:n]
}

func TestWriteVectors(t *testing.T) {
	var out []vector
	found := 0
	for i := 0; found < 4 && i < 64; i++ {
		pk, sk := mlkem768.NewKeyFromSeed(detSeed("keygen", i, mlkem768.KeySeedSize))
		_ = sk
		rawEK := make([]byte, mlkem768.PublicKeySize)
		pk.Pack(rawEK)
		ct := make([]byte, mlkem768.CiphertextSize)
		ss := make([]byte, mlkem768.SharedKeySize)
		pk.EncapsulateTo(ct, ss, detSeed("encaps", i, mlkem768.EncapsulationSeedSize))
		encEK, okEK := encodeEK(rawEK)
		encCT, okCT, err := encodeCt(ct, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !okEK || !okCT {
			continue // rejection: try the next index
		}
		found++
		for u := 0; u < 64; u++ {
			e := append([]byte{}, encEK...)
			e[ThatLen-1] = e[ThatLen-1]&^MSBByteMask | byte(u<<2)
			c := append([]byte{}, encCT...)
			c[ThatLen-1] = c[ThatLen-1]&^MSBByteMask | byte(u<<2)
			out = append(out, vector{"ek", "rejection", i, u, hex.EncodeToString(e), hex.EncodeToString(rawEK)})
			out = append(out, vector{"ct", "rejection", i, u, hex.EncodeToString(c), hex.EncodeToString(ct)})
			// Self-check.
			if r, err := DecodeEK(e); err != nil || hex.EncodeToString(r) != hex.EncodeToString(rawEK) {
				t.Fatal("EK vector does not decode")
			}
			if r, err := DecodeCiphertext(c); err != nil || hex.EncodeToString(r) != hex.EncodeToString(ct) {
				t.Fatal("CT vector does not decode")
			}
		}
		de, _ := EncodeEKDefault(rawEK, nil)
		dc, _ := EncodeCtDefault(ct, nil)
		out = append(out, vector{"ek", "default", i, 0, hex.EncodeToString(de), hex.EncodeToString(rawEK)})
		out = append(out, vector{"ct", "default", i, 0, hex.EncodeToString(dc), hex.EncodeToString(ct)})
	}
	b, _ := json.MarshalIndent(map[string]interface{}{
		"description": "Kemeleon ML-KEM-768 decoding vectors: decode(encoded) must equal expected_raw. " +
			"Rejection-encoding vectors cover all 64 values of the six unused accumulator bits " +
			"(byte 1123, mask 0xFC), which decoders must clear before decoding.",
		"vectors": out,
	}, "", " ")
	if err := os.WriteFile("../../artifact/vectors/kemeleon768_decode_vectors.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("%d vectors", len(out))
}
