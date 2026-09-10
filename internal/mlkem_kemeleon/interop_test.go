//go:build interop

package mlkem_kemeleon_test

// Cross-implementation tests against the Rust reference implementation
// (github.com/jmwample/kemeleon). Run with:
//
//	go test -tags interop -run TestInterop -v ./internal/mlkem_kemeleon/
//
// KEMELEON_VECTORS points at the JSON lines produced by the reference's
// `interop gen` example (default /tmp/rust_vectors.json); KEMELEON_GO_OUT, if
// set, receives Go-produced encodings for the reference to decode.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	mk "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

type vector struct {
	EkKmln string `json:"ek_kmln"`
	EkFips string `json:"ek_fips"`
	CtKmln string `json:"ct_kmln"`
	CtFips string `json:"ct_fips"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	path := os.Getenv("KEMELEON_VECTORS")
	if path == "" {
		path = "/tmp/rust_vectors.json"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no reference vectors at %s: %v", path, err)
	}
	var out []vector
	for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var v vector
		if err := json.Unmarshal(line, &v); err != nil {
			t.Fatalf("parse: %v", err)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		t.Skip("empty vector file")
	}
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// TestInteropDecodeReferenceEncodings decodes the reference implementation's
// Kemeleon encodings and checks we recover exactly the FIPS 203 bytes it
// reports. This is the Rust -> Go direction for both object types.
func TestInteropDecodeReferenceEncodings(t *testing.T) {
	vs := loadVectors(t)
	for i, v := range vs {
		gotEK, err := mk.DecodeEK(mustHex(t, v.EkKmln))
		if err != nil {
			t.Fatalf("vector %d: DecodeEK on reference encoding: %v", i, err)
		}
		if want := mustHex(t, v.EkFips); !bytes.Equal(gotEK, want) {
			t.Fatalf("vector %d: decoded EK mismatch\n got %x\nwant %x", i, gotEK[:32], want[:32])
		}
		gotCT, err := mk.DecodeCiphertext(mustHex(t, v.CtKmln))
		if err != nil {
			t.Fatalf("vector %d: DecodeCiphertext on reference encoding: %v", i, err)
		}
		if want := mustHex(t, v.CtFips); !bytes.Equal(gotCT, want) {
			t.Fatalf("vector %d: decoded ciphertext mismatch\n got %x\nwant %x", i, gotCT[:32], want[:32])
		}
	}
	t.Logf("decoded %d reference encapsulation keys and ciphertexts, all matching FIPS bytes", len(vs))
}

// TestInteropEncodeMatchesReference re-encodes the reference's FIPS
// encapsulation keys with our encoder and checks the result is bit-identical
// to the reference's encoding, except for the six high-order bits that both
// implementations fill with fresh randomness (IntegerRandomizeUnused).
func TestInteropEncodeMatchesReference(t *testing.T) {
	vs := loadVectors(t)
	for i, v := range vs {
		ours, err := mk.EncodeEKForTest(mustHex(t, v.EkFips))
		if err != nil {
			t.Fatalf("vector %d: %v", i, err)
		}
		theirs := mustHex(t, v.EkKmln)
		if !bytes.Equal(ours[:mk.ThatLen-1], theirs[:mk.ThatLen-1]) {
			t.Fatalf("vector %d: accumulator differs from the reference", i)
		}
		om := ours[mk.ThatLen-1] &^ mk.MSBByteMask
		tm := theirs[mk.ThatLen-1] &^ mk.MSBByteMask
		if om != tm {
			t.Fatalf("vector %d: top-byte data bits differ: ours %#02x theirs %#02x", i, om, tm)
		}
		if !bytes.Equal(ours[mk.ThatLen:], theirs[mk.ThatLen:]) {
			t.Fatalf("vector %d: seed rho differs", i)
		}
	}
	t.Logf("re-encoded %d reference keys; accumulators and seeds bit-identical", len(vs))
}

// TestInteropEmitGoEncodings writes Go-produced encodings for the reference to
// decode (the Go -> Rust direction).
func TestInteropEmitGoEncodings(t *testing.T) {
	path := os.Getenv("KEMELEON_GO_OUT")
	if path == "" {
		t.Skip("KEMELEON_GO_OUT not set")
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for i := 0; i < 200; i++ {
		kp, err := mk.GenerateKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		ec, err := mk.EncapsulateEncoded(kp.RawEncapsulationKey())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(f, "{\"ek_kmln\":\"%x\",\"ek_fips\":\"%x\",\"ct_kmln\":\"%x\",\"ct_fips\":\"%x\"}\n",
			kp.Representative(), kp.RawEncapsulationKey(), ec.Encoded, ec.Raw)
	}
	t.Logf("wrote 200 Go encodings to %s", path)
}

// TestInteropReferenceCiphertextUnusedBits documents a deviation we found in
// the Rust reference implementation (github.com/jmwample/kemeleon, v0.1.0-rc.1,
// commit cb139f8) while cross-validating this package.
//
// draft-irtf-cfrg-kemeleon specifies VectorEncodeR as ending with
// IntegerRandomizeUnused, and VectorDecodeR as beginning with
// IntegerClearUnused; EncodeCtxtR invokes VectorEncodeR, so a Kemeleon
// ciphertext's six unused high-order accumulator bits (for ML-KEM-768) must be
// random. The reference applies this to encapsulation keys but not to
// ciphertexts: its ciphertext accumulator leaves those bits zero, and its
// decoder does not mask them.
//
// The consequence is a fixed-zero fingerprint at a known offset in every
// encoded ciphertext, the same class of flaw Fifield found in obfs4proxy's
// Elligator 2 path. A censor testing byte 1123 detects such ciphertexts with a
// false-positive rate of 1/64 per message.
func TestInteropReferenceCiphertextUnusedBits(t *testing.T) {
	vs := loadVectors(t)
	patterns := map[byte]int{}
	for _, v := range vs {
		ct := mustHex(t, v.CtKmln)
		patterns[ct[mk.ThatLen-1]&mk.MSBByteMask]++
	}
	t.Logf("reference ciphertexts: %d distinct top-6-bit patterns over %d vectors (zero in %d)",
		len(patterns), len(vs), patterns[0])
	if len(patterns) != 1 || patterns[0] != len(vs) {
		t.Skip("reference appears to randomize ciphertext unused bits; deviation may be fixed upstream")
	}
	// Our own encoder must not share the deviation.
	ours := map[byte]int{}
	for i := 0; i < 200; i++ {
		kp, err := mk.GenerateKeyPair(nil)
		if err != nil {
			t.Fatal(err)
		}
		ec, err := mk.EncapsulateEncoded(kp.RawEncapsulationKey())
		if err != nil {
			t.Fatal(err)
		}
		ours[ec.Encoded[mk.ThatLen-1]&mk.MSBByteMask]++
	}
	if len(ours) < 32 {
		t.Fatalf("our ciphertext unused bits look non-random: only %d distinct patterns", len(ours))
	}
	t.Logf("this implementation: %d distinct patterns over 200 ciphertexts (draft-conformant)", len(ours))
}
