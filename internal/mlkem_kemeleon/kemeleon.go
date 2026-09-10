// Package mlkem_kemeleon implements Kemeleon encoding of ML-KEM-768
// encapsulation keys, producing byte strings that are computationally
// indistinguishable from uniform random data.
//
// It is a Go port of the Rust crate jmwample/kemeleon (specifically
// src/kemeleon/encapsulation_key.rs), intended to replace the Elligator 2
// mapping used for X25519 keys in the obfs4 handshake with a post-quantum
// ML-KEM-768 equivalent.
//
// The underlying ML-KEM-768 implementation is github.com/cloudflare/circl,
// which is already a dependency of lyrebird (so no new module or Go version
// bump is required).
package mlkem_kemeleon // import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	K        = 3    // module rank for ML-KEM-768
	N        = 256  // polynomial degree
	Q        = 3329 // modulus
	RhoLen   = 32   // public seed, appended at the end of the FIPS encoding
	CoeffLen = K * N // = 768 coefficients total

	// FIPSCoeffBytes is the size of the 12-bit packed coefficient block in a
	// FIPS ML-KEM-768 encapsulation key: K*256*12/8 = 1152 bytes.
	FIPSCoeffBytes = K * N * 12 / 8 // = 1152

	// RawEKLen is the raw FIPS ML-KEM-768 encapsulation key length.
	RawEKLen = FIPSCoeffBytes + RhoLen // = 1184

	// ThatLen is the byte length of the mixed-radix accumulator
	// r = sum(coeff[i] * q^i). The maximum value q^768 - 1 has bit length 8987,
	// which rounds up to 1124 bytes (8992 bits).
	ThatLen = 1124

	// EncodedLen is the total Kemeleon representative length: r || rho.
	EncodedLen = ThatLen + RhoLen // = 1156

	// CiphertextLen is the ML-KEM-768 ciphertext length.
	CiphertextLen = 1088

	// SharedSecretLen is the ML-KEM shared-secret length.
	SharedSecretLen = 32

	// MSBByteMask selects the bits of the high-order byte (the last byte in the
	// little-endian accumulator) that must be zero for the encoding to be
	// accepted. q^768 occupies 8987 bits; the top byte therefore has its low 3
	// bits as real data (bit 8984..8986) and its top 5 bits unused. The Kemeleon
	// rejection test requires bit 8986 (and above) to be clear, i.e. the top 6
	// bits of the last byte must be zero -> mask 0b1111_1100 = 0xFC. This matches
	// the Rust reference (MlKem768Params::MSB_BITMASK = 0b1111_1100).
	MSBByteMask = byte(0xFC)
)

// unpack12 unpacks len(b)*8/12 little-endian 12-bit values from b (FIPS ML-KEM
// packing). Two coefficients occupy three bytes:
//
//	out[0] = b0 | (b1&0x0F)<<8
//	out[1] = b1>>4 | b2<<4
func unpack12(b []byte) []uint16 {
	n := len(b) * 2 / 3
	out := make([]uint16, n)
	for i := 0; i < n/2; i++ {
		b0, b1, b2 := b[3*i], b[3*i+1], b[3*i+2]
		out[2*i] = uint16(b0) | (uint16(b1&0x0F) << 8)
		out[2*i+1] = uint16(b1>>4) | (uint16(b2) << 4)
	}
	return out
}

// pack12 packs coefficients (each < 4096) into 12-bit FIPS little-endian
// encoding, the inverse of unpack12.
func pack12(b []byte, coeffs []uint16) {
	for i := 0; i < len(coeffs)/2; i++ {
		c0, c1 := coeffs[2*i], coeffs[2*i+1]
		b[3*i] = byte(c0)
		b[3*i+1] = byte(c0>>8) | byte(c1<<4)
		b[3*i+2] = byte(c1 >> 4)
	}
}

// encodeEK encodes a raw FIPS ML-KEM-768 encapsulation key (1184 bytes) into a
// Kemeleon representative (1156 bytes). It returns (encoded, true) on success or
// (nil, false) when the high-order-bit rejection test fails.
//
// The accumulator r = sum(coeff[i] * q^i) is serialized little-endian into
// ThatLen bytes (matching the Rust vector_encode), and the representative is
// r_le || rho.
func encodeEK(fipsEK []byte) ([]byte, bool) {
	if len(fipsEK) != RawEKLen {
		return nil, false
	}

	rho := fipsEK[FIPSCoeffBytes : FIPSCoeffBytes+RhoLen]
	coeffs := unpack12(fipsEK[:FIPSCoeffBytes]) // len == CoeffLen

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

	// Serialize little-endian into exactly ThatLen bytes.
	out := make([]byte, EncodedLen)
	rLE := out[:ThatLen]
	rBytes := r.Bytes() // big-endian
	for i, bv := range rBytes {
		// little-endian position of big-endian byte i
		rLE[len(rBytes)-1-i] = bv
	}

	// Rejection: high-order byte (last little-endian byte) must have no bits set
	// under the mask.
	if rLE[ThatLen-1]&MSBByteMask != 0 {
		return nil, false
	}

	// IntegerRandomizeUnused (draft-irtf-cfrg-kemeleon): the bits under the
	// mask are never used by an accepted accumulator, so fill them with fresh
	// random bits. Without this step every representative would carry six
	// fixed-zero bits at a known offset, an on-wire fingerprint with a 1/64
	// false-positive rate. The decoder masks these bits off again.
	var rb [1]byte
	if _, err := io.ReadFull(rand.Reader, rb[:]); err != nil {
		return nil, false
	}
	rLE[ThatLen-1] |= rb[0] & MSBByteMask

	copy(out[ThatLen:], rho)
	return out, true
}

// decodeEK decodes a Kemeleon representative (1156 bytes: r_le || rho) back into
// a raw FIPS ML-KEM-768 encapsulation key (1184 bytes). It returns (nil, false)
// if the encoding is malformed (a recovered coefficient >= q, or leftover value
// after extracting all coefficients).
func decodeEK(encoded []byte) ([]byte, bool) {
	rLE := encoded[:ThatLen] // little-endian accumulator
	rho := encoded[ThatLen:] // 32 bytes

	// big.Int wants big-endian; reverse rLE, clearing the randomized unused
	// bits of the high-order byte (see encodeEK).
	beBuf := make([]byte, ThatLen)
	for i := 0; i < ThatLen; i++ {
		beBuf[ThatLen-1-i] = rLE[i]
	}
	beBuf[0] &^= MSBByteMask
	r := new(big.Int).SetBytes(beBuf)

	qBig := big.NewInt(Q)
	rem := new(big.Int)
	coeffs := make([]uint16, CoeffLen)
	for i := 0; i < CoeffLen; i++ {
		r.DivMod(r, qBig, rem)
		c := rem.Uint64()
		if c >= Q {
			return nil, false
		}
		coeffs[i] = uint16(c)
	}
	if r.Sign() != 0 {
		return nil, false
	}

	fipsEK := make([]byte, RawEKLen)
	pack12(fipsEK[:FIPSCoeffBytes], coeffs)
	copy(fipsEK[FIPSCoeffBytes:], rho)
	return fipsEK, true
}

// KeyPair holds an ML-KEM-768 keypair together with its Kemeleon-encoded
// representative.
type KeyPair struct {
	dk             *mlkem768.PrivateKey
	representative []byte // Kemeleon-encoded encapsulation key (EncodedLen bytes)
	rawEK          []byte // raw FIPS encapsulation key (RawEKLen bytes)
}

// GenerateKeyPair generates a fresh ML-KEM-768 keypair, retrying with new keys
// until the encapsulation key encodes successfully under Kemeleon. Expected
// attempts ~= 1/0.83 ≈ 1.2. If rng is nil, crypto/rand is used.
func GenerateKeyPair(rng io.Reader) (*KeyPair, error) {
	if rng == nil {
		rng = rand.Reader
	}
	for attempts := 0; attempts < 100; attempts++ {
		pk, sk, err := mlkem768.GenerateKeyPair(rng)
		if err != nil {
			return nil, fmt.Errorf("mlkem_kemeleon: keygen: %w", err)
		}
		raw := make([]byte, mlkem768.PublicKeySize)
		pk.Pack(raw)

		encoded, ok := encodeEK(raw)
		if !ok {
			continue // rejection: high bit set, regenerate
		}
		return &KeyPair{dk: sk, representative: encoded, rawEK: raw}, nil
	}
	return nil, errors.New("mlkem_kemeleon: rejection sampling exceeded 100 attempts")
}

// Representative returns a fresh copy of the Kemeleon-encoded encapsulation key
// (EncodedLen bytes). This replaces the 32-byte Elligator 2 representative on
// the wire.
func (kp *KeyPair) Representative() []byte {
	out := make([]byte, EncodedLen)
	copy(out, kp.representative)
	return out
}

// RawEncapsulationKey returns a fresh copy of the raw ML-KEM-768 encapsulation
// key (RawEKLen bytes).
func (kp *KeyPair) RawEncapsulationKey() []byte {
	out := make([]byte, len(kp.rawEK))
	copy(out, kp.rawEK)
	return out
}

// Decapsulate recovers the shared secret from a ciphertext using this keypair.
func (kp *KeyPair) Decapsulate(ct []byte) ([]byte, error) {
	if len(ct) != CiphertextLen {
		return nil, fmt.Errorf("mlkem_kemeleon: ciphertext must be %d bytes, got %d", CiphertextLen, len(ct))
	}
	ss := make([]byte, SharedSecretLen)
	kp.dk.DecapsulateTo(ss, ct)
	return ss, nil
}

// Encapsulate generates a ciphertext and shared secret for the given raw
// ML-KEM-768 encapsulation key. Returns (ciphertext, sharedSecret, error).
func Encapsulate(rawEK []byte) ([]byte, []byte, error) {
	if len(rawEK) != RawEKLen {
		return nil, nil, fmt.Errorf("mlkem_kemeleon: raw EK must be %d bytes, got %d", RawEKLen, len(rawEK))
	}
	ek := new(mlkem768.PublicKey)
	if err := ek.Unpack(rawEK); err != nil {
		return nil, nil, fmt.Errorf("mlkem_kemeleon: invalid EK: %w", err)
	}
	seed := make([]byte, mlkem768.EncapsulationSeedSize)
	if _, err := io.ReadFull(rand.Reader, seed); err != nil {
		return nil, nil, fmt.Errorf("mlkem_kemeleon: seed: %w", err)
	}
	ct := make([]byte, CiphertextLen)
	ss := make([]byte, SharedSecretLen)
	ek.EncapsulateTo(ct, ss, seed)
	return ct, ss, nil
}

// ProbeEncodeAccepts reports whether a raw FIPS encapsulation key would be
// accepted by Kemeleon encoding on a single attempt (i.e. the high-order-bit
// rejection test passes). It exists to let tests measure the rejection rate
// without the retry loop in GenerateKeyPair.
func ProbeEncodeAccepts(rawEK []byte) bool {
	_, ok := encodeEK(rawEK)
	return ok
}

// DecodeEK decodes a Kemeleon representative (EncodedLen bytes) back to a raw
// ML-KEM-768 encapsulation key (RawEKLen bytes). It returns an error if the
// input length is wrong or the encoding is malformed.
func DecodeEK(encoded []byte) ([]byte, error) {
	if len(encoded) != EncodedLen {
		return nil, fmt.Errorf("mlkem_kemeleon: encoded EK must be %d bytes, got %d", EncodedLen, len(encoded))
	}
	rawEK, ok := decodeEK(encoded)
	if !ok {
		return nil, errors.New("mlkem_kemeleon: invalid Kemeleon encoding")
	}
	return rawEK, nil
}
