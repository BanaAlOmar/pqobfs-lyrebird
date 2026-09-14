package mlkem_kemeleon

// Kemeleon ciphertext encoding for ML-KEM-768 (rejection-sampling variant),
// following Kemeleon.EncodeCtxtR / DecodeCtxtR of draft-irtf-cfrg-kemeleon.
//
// An ML-KEM ciphertext c = (c_1, c_2) carries k*n coefficients compressed to
// d_u bits and n coefficients compressed to d_v bits. Compression is not
// equidistributed (Compress_10 maps 3329 residues onto 1024 values, so 257
// outputs have four preimages and 767 have three), which leaves the raw
// ciphertext distinguishable from uniform bytes even though every individual
// bit is balanced. The encoding therefore decompresses c_1, resamples a
// uniform preimage under the compression map, and runs the same mixed-radix
// accumulate-and-reject step used for encapsulation keys; c_2 is carried
// verbatim with a small rejection that removes its own bias.
//
// Sizes for ML-KEM-768 (k=3, n=256, d_u=10, d_v=4):
//
//	raw c_1 = k*n*d_u/8 = 960 B     raw c_2 = n*d_v/8 = 128 B    raw ct = 1088 B
//	encoded  = ThatLen (1124) + 128 = 1252 B
//
// The single-attempt acceptance probability is ~0.77: ~0.83 from the
// accumulator's top-bit test and ~0.92 from the c_2 test.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	// DU and DV are the ML-KEM-768 compression parameters.
	DU = 10
	DV = 4

	// C1Bytes and C2Bytes are the raw sizes of the two ciphertext components.
	C1Bytes = CoeffLen * DU / 8 // 960
	C2Bytes = N * DV / 8        // 128

	// EncodedCtLen is the Kemeleon-encoded ciphertext length: accumulator || c_2.
	EncodedCtLen = ThatLen + C2Bytes // 1124 + 128 = 1252
)

// compress implements FIPS 203 Compress_d: round(2^d / q * x) mod 2^d, with
// round-half-up, for x in Z_q.
func compress(x uint32, d uint) uint16 {
	num := uint64(x)<<d*2 + uint64(Q) // 2*(x<<d) + q, for round-half-up
	return uint16((num / (2 * uint64(Q))) & ((1 << d) - 1))
}

// decompress implements FIPS 203 Decompress_d: round(q / 2^d * y),
// round-half-up, for y in [0, 2^d).
func decompress(y uint16, d uint) uint32 {
	num := uint64(y)*uint64(Q)*2 + (1 << d)
	return uint32(num / (2 << d))
}

// unpackBits unpacks n little-endian d-bit values from b (FIPS 203 byte
// packing, least-significant bit first).
func unpackBits(b []byte, d uint, n int) []uint16 {
	out := make([]uint16, n)
	var acc uint64
	var accBits uint
	bi := 0
	for i := 0; i < n; i++ {
		for accBits < d {
			acc |= uint64(b[bi]) << accBits
			accBits += 8
			bi++
		}
		out[i] = uint16(acc & ((1 << d) - 1))
		acc >>= d
		accBits -= d
	}
	return out
}

// packBits is the inverse of unpackBits.
func packBits(b []byte, vals []uint16, d uint) {
	var acc uint64
	var accBits uint
	bi := 0
	for _, v := range vals {
		acc |= uint64(v&((1<<d)-1)) << accBits
		accBits += d
		for accBits >= 8 {
			b[bi] = byte(acc)
			acc >>= 8
			accBits -= 8
			bi++
		}
	}
	if accBits > 0 {
		b[bi] = byte(acc)
	}
}

// samplePreimage implements SamplePreimage(d, u, c) of the draft for d = 10:
// given the decompressed value u and the compressed value c, it returns a
// uniformly chosen element of the preimage set of c under Compress_10.
func samplePreimage(u uint32, c uint16, rng io.Reader) (uint32, error) {
	var lo, hi int32 // inclusive offset range
	switch {
	case compress(addModQ(u, 2), DU) == c:
		lo, hi = -1, 2
	case compress(addModQ(u, Q-2), DU) == c:
		lo, hi = -2, 1
	default:
		lo, hi = -1, 1
	}
	n := int64(hi - lo + 1)
	off, err := randInt(rng, n)
	if err != nil {
		return 0, err
	}
	return addModQ(u, uint32((int32(off)+lo+int32(Q))%int32(Q))), nil
}

// addModQ returns (a + b) mod q for a, b < q.
func addModQ(a, b uint32) uint32 {
	s := a + b
	if s >= Q {
		s -= Q
	}
	return s
}

// randInt returns a uniform integer in [0, n).
func randInt(rng io.Reader, n int64) (int64, error) {
	if rng == nil {
		rng = rand.Reader
	}
	v, err := rand.Int(rng, big.NewInt(n))
	if err != nil {
		return 0, err
	}
	return v.Int64(), nil
}

// encodeCt encodes a raw ML-KEM-768 ciphertext (1088 bytes) into a Kemeleon
// representative (1252 bytes). It returns (nil, false) when either rejection
// test fires; the caller re-runs encapsulation with fresh randomness.
func encodeCt(ct []byte, rng io.Reader) ([]byte, bool, error) {
	if len(ct) != CiphertextLen {
		return nil, false, fmt.Errorf("mlkem_kemeleon: ciphertext must be %d bytes, got %d", CiphertextLen, len(ct))
	}
	c1 := unpackBits(ct[:C1Bytes], DU, CoeffLen)
	c2 := ct[C1Bytes:]

	// Decompress c_1 and resample a uniform preimage for each coefficient.
	coeffs := make([]uint16, CoeffLen)
	for i, c := range c1 {
		u, err := samplePreimage(decompress(c, DU), c, rng)
		if err != nil {
			return nil, false, err
		}
		coeffs[i] = uint16(u)
	}

	// VectorEncodeR: mixed-radix accumulate, reject on a set top bit.
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
	out := make([]byte, EncodedCtLen)
	rLE := out[:ThatLen]
	rBytes := r.Bytes() // big-endian
	for i, bv := range rBytes {
		rLE[len(rBytes)-1-i] = bv
	}
	if rLE[ThatLen-1]&MSBByteMask != 0 {
		return nil, false, nil
	}

	// c_2 rejection: for each zero coefficient, reject with probability
	// 1/ceil(q / 2^dv). This removes the bias that Compress_dv leaves on the
	// value 0, whose preimage set is one larger than the others.
	const c2RejectDenom = (Q + (1 << DV) - 1) >> DV // ceil(3329/16) = 209
	c2vals := unpackBits(c2, DV, N)
	for _, v := range c2vals {
		if v != 0 {
			continue
		}
		k, err := randInt(rng, c2RejectDenom)
		if err != nil {
			return nil, false, err
		}
		if k == 0 {
			return nil, false, nil
		}
	}

	// IntegerRandomizeUnused on the accumulator's unused top bits.
	var rb [1]byte
	if _, err := io.ReadFull(orRand(rng), rb[:]); err != nil {
		return nil, false, err
	}
	rLE[ThatLen-1] |= rb[0] & MSBByteMask

	copy(out[ThatLen:], c2)
	return out, true, nil
}

// decodeCt decodes a Kemeleon ciphertext representative (1252 bytes) back to a
// raw ML-KEM-768 ciphertext (1088 bytes).
func decodeCt(ec []byte) ([]byte, bool) {
	if len(ec) != EncodedCtLen {
		return nil, false
	}
	rLE := ec[:ThatLen]
	c2 := ec[ThatLen:]

	beBuf := make([]byte, ThatLen)
	for i := 0; i < ThatLen; i++ {
		beBuf[ThatLen-1-i] = rLE[i]
	}
	beBuf[0] &^= MSBByteMask // IntegerClearUnused
	r := new(big.Int).SetBytes(beBuf)

	qBig := big.NewInt(Q)
	rem := new(big.Int)
	c1 := make([]uint16, CoeffLen)
	for i := 0; i < CoeffLen; i++ {
		r.DivMod(r, qBig, rem)
		u := rem.Uint64()
		if u >= Q {
			return nil, false
		}
		c1[i] = compress(uint32(u), DU)
	}
	if r.Sign() != 0 {
		return nil, false
	}

	ct := make([]byte, CiphertextLen)
	packBits(ct[:C1Bytes], c1, DU)
	copy(ct[C1Bytes:], c2)
	return ct, true
}

func orRand(rng io.Reader) io.Reader {
	if rng == nil {
		return rand.Reader
	}
	return rng
}

// EncodedCiphertext bundles a Kemeleon-encoded ciphertext with its shared
// secret.
type EncodedCiphertext struct {
	Encoded      []byte // EncodedCtLen bytes, computationally uniform
	Raw          []byte // CiphertextLen bytes
	SharedSecret []byte // SharedSecretLen bytes
}

// maxCtAttempts bounds the encapsulation rejection loop. The per-attempt
// acceptance probability is ~0.77, so 100 attempts fail with probability
// below 2^-140.
const maxCtAttempts = 100

// EncapsulateEncoded encapsulates to a raw ML-KEM-768 encapsulation key,
// retrying with fresh randomness until the ciphertext encodes successfully
// under Kemeleon. Expected attempts ~= 1/0.77 ~= 1.3.
func EncapsulateEncoded(rawEK []byte) (*EncodedCiphertext, error) {
	for i := 0; i < maxCtAttempts; i++ {
		ct, ss, err := Encapsulate(rawEK)
		if err != nil {
			return nil, err
		}
		enc, ok, err := encodeCt(ct, nil)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue // rejection: re-encapsulate
		}
		return &EncodedCiphertext{Encoded: enc, Raw: ct, SharedSecret: ss}, nil
	}
	return nil, errors.New("mlkem_kemeleon: ciphertext rejection sampling exceeded 100 attempts")
}

// DecodeCiphertext decodes a Kemeleon ciphertext representative back to a raw
// ML-KEM-768 ciphertext.
func DecodeCiphertext(encoded []byte) ([]byte, error) {
	if len(encoded) != EncodedCtLen {
		return nil, fmt.Errorf("mlkem_kemeleon: encoded ciphertext must be %d bytes, got %d", EncodedCtLen, len(encoded))
	}
	ct, ok := decodeCt(encoded)
	if !ok {
		return nil, errors.New("mlkem_kemeleon: invalid Kemeleon ciphertext encoding")
	}
	return ct, nil
}

// ProbeEncodeCtAccepts reports whether a raw ciphertext would be accepted by
// the ciphertext encoding on a single attempt. It exists so tests can measure
// the acceptance rate without the retry loop.
func ProbeEncodeCtAccepts(ct []byte) bool {
	_, ok, err := encodeCt(ct, nil)
	return err == nil && ok
}

// unused keeps binary imported for potential future fixed-width paths.
var _ = binary.LittleEndian

// --- test helpers (exported for the package's external test files) ---

// CompressForTest exposes the FIPS 203 compression map for analysis code.
func CompressForTest(x uint32, d uint) uint16 { return compress(x, d) }

// UnpackBitsForTest exposes the d-bit unpacker for analysis code.
func UnpackBitsForTest(b []byte, d uint, n int) []uint16 { return unpackBits(b, d, n) }

// RandForTest fills b with uniform random bytes.
func RandForTest(b []byte) {
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(err)
	}
}

// EncodeEKForTest exposes the encapsulation-key encoder for cross-implementation
// tests. It returns an error if the key is not encodable (rejection).
func EncodeEKForTest(fipsEK []byte) ([]byte, error) {
	out, ok := encodeEK(fipsEK)
	if !ok {
		return nil, errors.New("mlkem_kemeleon: key not encodable")
	}
	return out, nil
}
