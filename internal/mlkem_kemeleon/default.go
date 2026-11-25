package mlkem_kemeleon

// Default (non-rejecting) Kemeleon encoding for ML-KEM-768.
//
// Instead of rejecting accumulators whose top bits are set, the default
// variant of draft-irtf-cfrg-kemeleon encodes each 256-coefficient polynomial
// separately: the digits t_0..t_255 in Z_q give r = sum t_i q^i < q^256, and
// the encoder outputs r + m q^256 with m drawn uniformly from
// [0, floor(2^3072 / q^256)), serialized little-endian in 3,072 bits
// (384 bytes). The result is within statistical distance q^256 / 2^3072,
// about 2^-76, of uniform per polynomial, and the encoder never fails, so
// key generation and encapsulation need no retries.
//
// Sizes for ML-KEM-768: encapsulation key 3 x 384 + 32 = 1,184 bytes (the
// same as raw FIPS 203); ciphertext 4 x 384 = 1,536 bytes (c_1's three
// polynomials after preimage sampling under Compress_10, plus c_2's
// polynomial after preimage sampling under Compress_4).

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

const (
	// DefaultPolyBytes is the encoded size of one polynomial: 3,072 bits.
	DefaultPolyBytes = 384
	// DefaultEKLen is the default-encoded encapsulation key length.
	DefaultEKLen = K*DefaultPolyBytes + RhoLen // 1184
	// DefaultCtLen is the default-encoded ciphertext length.
	DefaultCtLen = (K + 1) * DefaultPolyBytes // 1536
	// defaultPolyAccBytes holds r < q^256 (2,996 bits).
	defaultPolyAccBytes = 375
)

var (
	qPow256 = new(big.Int).Exp(big.NewInt(Q), big.NewInt(N), nil)
	// defaultM is the number of admissible multiples: floor(2^3072 / q^256).
	defaultM = new(big.Int).Div(new(big.Int).Lsh(big.NewInt(1), 8*DefaultPolyBytes), qPow256)
	// preimages4[v] lists the x in Z_q with Compress_4(x) = v.
	preimages4 = func() [16][]uint16 {
		var p [16][]uint16
		for x := uint32(0); x < Q; x++ {
			v := compress(x, DV)
			p[v] = append(p[v], uint16(x))
		}
		return p
	}()
)

func leToBig(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i := range b {
		be[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(be)
}

func bigToLE(x *big.Int, n int) []byte {
	be := x.Bytes()
	out := make([]byte, n)
	for i, v := range be {
		out[len(be)-1-i] = v
	}
	return out
}

// encodePolyDefault encodes 256 digits in Z_q into 384 bytes.
func encodePolyDefault(dst []byte, coeffs []uint16, rng io.Reader) error {
	acc := make([]byte, defaultPolyAccBytes)
	radixEncodeN(acc, coeffs)
	m, err := rand.Int(orRand(rng), defaultM)
	if err != nil {
		return err
	}
	v := new(big.Int).Mul(m, qPow256)
	v.Add(v, leToBig(acc))
	copy(dst, bigToLE(v, DefaultPolyBytes))
	return nil
}

// decodePolyDefault recovers 256 digits from a 384-byte encoding.
func decodePolyDefault(coeffs []uint16, src []byte) bool {
	v := leToBig(src)
	v.Mod(v, qPow256)
	return radixDecodeN(coeffs, bigToLE(v, defaultPolyAccBytes))
}

// EncodeEKDefault encodes a raw FIPS ML-KEM-768 encapsulation key with the
// default (non-rejecting) encoding.
func EncodeEKDefault(fipsEK []byte, rng io.Reader) ([]byte, error) {
	if len(fipsEK) != RawEKLen {
		return nil, fmt.Errorf("mlkem_kemeleon: raw EK must be %d bytes", RawEKLen)
	}
	coeffs := unpack12(fipsEK[:FIPSCoeffBytes])
	for _, c := range coeffs {
		if c >= Q {
			return nil, errors.New("mlkem_kemeleon: EK coefficient out of range")
		}
	}
	out := make([]byte, DefaultEKLen)
	for p := 0; p < K; p++ {
		if err := encodePolyDefault(out[p*DefaultPolyBytes:(p+1)*DefaultPolyBytes], coeffs[p*N:(p+1)*N], rng); err != nil {
			return nil, err
		}
	}
	copy(out[K*DefaultPolyBytes:], fipsEK[FIPSCoeffBytes:])
	return out, nil
}

// DecodeEKDefault inverts EncodeEKDefault. Every 1,184-byte string decodes.
func DecodeEKDefault(enc []byte) ([]byte, error) {
	if len(enc) != DefaultEKLen {
		return nil, fmt.Errorf("mlkem_kemeleon: default EK must be %d bytes", DefaultEKLen)
	}
	coeffs := make([]uint16, CoeffLen)
	for p := 0; p < K; p++ {
		if !decodePolyDefault(coeffs[p*N:(p+1)*N], enc[p*DefaultPolyBytes:(p+1)*DefaultPolyBytes]) {
			return nil, errors.New("mlkem_kemeleon: invalid default EK encoding")
		}
	}
	out := make([]byte, RawEKLen)
	pack12(out[:FIPSCoeffBytes], coeffs)
	copy(out[FIPSCoeffBytes:], enc[K*DefaultPolyBytes:])
	return out, nil
}

// EncodeCtDefault encodes a raw ML-KEM-768 ciphertext with the default
// encoding. It never fails for well-formed input.
func EncodeCtDefault(ct []byte, rng io.Reader) ([]byte, error) {
	if len(ct) != CiphertextLen {
		return nil, fmt.Errorf("mlkem_kemeleon: ciphertext must be %d bytes", CiphertextLen)
	}
	c1 := unpackBits(ct[:C1Bytes], DU, CoeffLen)
	c2 := unpackBits(ct[C1Bytes:], DV, N)
	coeffs := make([]uint16, CoeffLen+N)
	for i, c := range c1 {
		u, err := samplePreimage(decompress(c, DU), c, rng)
		if err != nil {
			return nil, err
		}
		coeffs[i] = uint16(u)
	}
	for i, c := range c2 {
		set := preimages4[c]
		j, err := randInt(rng, int64(len(set)))
		if err != nil {
			return nil, err
		}
		coeffs[CoeffLen+i] = set[j]
	}
	out := make([]byte, DefaultCtLen)
	for p := 0; p < K+1; p++ {
		if err := encodePolyDefault(out[p*DefaultPolyBytes:(p+1)*DefaultPolyBytes], coeffs[p*N:(p+1)*N], rng); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// DecodeCtDefault inverts EncodeCtDefault. Every 1,536-byte string decodes.
func DecodeCtDefault(enc []byte) ([]byte, error) {
	if len(enc) != DefaultCtLen {
		return nil, fmt.Errorf("mlkem_kemeleon: default ciphertext must be %d bytes", DefaultCtLen)
	}
	coeffs := make([]uint16, CoeffLen+N)
	for p := 0; p < K+1; p++ {
		if !decodePolyDefault(coeffs[p*N:(p+1)*N], enc[p*DefaultPolyBytes:(p+1)*DefaultPolyBytes]) {
			return nil, errors.New("mlkem_kemeleon: invalid default ciphertext encoding")
		}
	}
	c1 := make([]uint16, CoeffLen)
	for i := range c1 {
		c1[i] = compress(uint32(coeffs[i]), DU)
	}
	c2 := make([]uint16, N)
	for i := range c2 {
		c2[i] = compress(uint32(coeffs[CoeffLen+i]), DV)
	}
	ct := make([]byte, CiphertextLen)
	packBits(ct[:C1Bytes], c1, DU)
	packBits(ct[C1Bytes:], c2, DV)
	return ct, nil
}

// GenerateKeyPairDefault generates an ML-KEM-768 key pair and its default
// Kemeleon representative. It never retries.
func GenerateKeyPairDefault(rng io.Reader) (*KeyPair, error) {
	pk, sk, err := mlkem768.GenerateKeyPair(rng)
	afterAVX()
	if err != nil {
		return nil, err
	}
	raw := make([]byte, mlkem768.PublicKeySize)
	pk.Pack(raw)
	afterAVX()
	enc, err := EncodeEKDefault(raw, rng)
	if err != nil {
		return nil, err
	}
	return &KeyPair{dk: sk, representative: enc, rawEK: raw}, nil
}

// EncapsulateEncodedDefault encapsulates to a raw key and default-encodes the
// ciphertext. Exactly one encapsulation, no retries.
func EncapsulateEncodedDefault(rawEK []byte) (*EncodedCiphertext, error) {
	ct, ss, err := Encapsulate(rawEK)
	if err != nil {
		return nil, err
	}
	enc, err := EncodeCtDefault(ct, nil)
	if err != nil {
		return nil, err
	}
	return &EncodedCiphertext{Encoded: enc, Raw: ct, SharedSecret: ss}, nil
}

// RepresentativeLen is the length of the stored representative:
// EncodedLen (rejection) or DefaultEKLen (default encoding).
func (kp *KeyPair) RepresentativeLen() int { return len(kp.representative) }
