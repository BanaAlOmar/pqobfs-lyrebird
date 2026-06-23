package mlkem_kemeleon_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	mk "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

// rawEK generates a fresh raw FIPS ML-KEM-768 encapsulation key (1184 bytes).
func rawEK(t *testing.T) []byte {
	t.Helper()
	pk, _, err := mlkem768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	buf := make([]byte, mlkem768.PublicKeySize)
	pk.Pack(buf)
	return buf
}

// TestEncodeDecodeRoundTrip generates raw EKs, runs them through Kemeleon
// encode+decode (when encoding succeeds), and verifies the raw bytes survive.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	const trials = 50
	for i := 0; i < trials; i++ {
		kp, err := mk.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		decoded, err := mk.DecodeEK(kp.Representative())
		if err != nil {
			t.Fatalf("DecodeEK: %v", err)
		}
		if !bytes.Equal(decoded, kp.RawEncapsulationKey()) {
			t.Fatalf("round-trip mismatch for keypair %d", i)
		}
	}
}

// TestRejectionRate measures the Kemeleon encode success rate over many raw EKs
// and asserts it lands near the paper's ~0.83 (Table III).
func TestRejectionRate(t *testing.T) {
	const trials = 10000
	successes := 0
	for i := 0; i < trials; i++ {
		if mk.ProbeEncodeAccepts(rawEK(t)) {
			successes++
		}
	}
	rate := float64(successes) / float64(trials)
	t.Logf("Kemeleon pk encode success rate: %.3f (%d/%d), paper ~0.83", rate, successes, trials)
	if rate < 0.75 || rate > 0.91 {
		t.Fatalf("rejection rate %.3f out of expected range [0.75, 0.91]", rate)
	}
}

// TestEncodedLength asserts Representative() is always exactly EncodedLen bytes.
func TestEncodedLength(t *testing.T) {
	for i := 0; i < 20; i++ {
		kp, err := mk.GenerateKeyPair(nil)
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		if got := len(kp.Representative()); got != mk.EncodedLen {
			t.Fatalf("representative length = %d, want %d", got, mk.EncodedLen)
		}
	}
}

// TestGenerateKeyPairSucceeds calls GenerateKeyPair repeatedly with no errors.
func TestGenerateKeyPairSucceeds(t *testing.T) {
	for i := 0; i < 10; i++ {
		if _, err := mk.GenerateKeyPair(nil); err != nil {
			t.Fatalf("GenerateKeyPair attempt %d: %v", i, err)
		}
	}
}

// TestEncapsulateDecapsulate checks the KEM round-trip via the raw EK.
func TestEncapsulateDecapsulate(t *testing.T) {
	kp, err := mk.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ct, ssEnc, err := mk.Encapsulate(kp.RawEncapsulationKey())
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	ssDec, err := kp.Decapsulate(ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatalf("shared secret mismatch:\n enc=%x\n dec=%x", ssEnc, ssDec)
	}
}

// TestDecodeEKInvalidLength expects an error for wrong-length input.
func TestDecodeEKInvalidLength(t *testing.T) {
	if _, err := mk.DecodeEK(make([]byte, 100)); err == nil {
		t.Fatal("expected error for 100-byte input, got nil")
	}
}

// TestDecodeEKGarbage feeds random EncodedLen-byte input; it must not panic
// (an error is acceptable, as is a recovered raw EK).
func TestDecodeEKGarbage(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DecodeEK panicked on garbage input: %v", r)
		}
	}()
	garbage := make([]byte, mk.EncodedLen)
	if _, err := io.ReadFull(rand.Reader, garbage); err != nil {
		t.Fatalf("rand: %v", err)
	}
	_, _ = mk.DecodeEK(garbage) // result ignored; only the no-panic property matters
}
