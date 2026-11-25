package mlkem_kemeleon

// Fixed-width mixed-radix conversion for the Kemeleon accumulator.
//
// Kemeleon interprets the k*n = 768 coefficients t_i in Z_q as the digits of
// r = sum_i t_i * q^i and serializes r little-endian in ThatLen = 1124 bytes.
// The original implementation used math/big: 768 big.Int multiplications to
// encode and 768 big.Int DivMod calls to decode, which dominated the
// post-quantum handshake cost (about 0.6 ms per decode on a 2.8 GHz Xeon).
//
// This file replaces both directions with fixed-width 64-bit limb arithmetic
// on a stack-allocated array. Coefficients are processed five at a time:
// q^5 = 408,854,682,322,747,649 < 2^59, so a chunk of five digits fits in one
// uint64 and the accumulator is advanced by a single-limb multiply (encode) or
// reduced by a single-limb division (decode). Decoding uses division by the
// invariant divisor q^5 with a precomputed reciprocal (Möller and Granlund,
// "Improved division by invariant integers", IEEE TC 2011), avoiding the
// hardware DIV instruction in the inner loop.
//
// The functions operate on public data only (wire representations), so they
// are not constant-time and do not need to be.

import (
	"encoding/binary"
	"math/bits"
)

const (
	radixChunk = 5                         // digits per limb operation
	radixD     = uint64(Q * Q * Q * Q * Q) // q^5 < 2^59
	radixShift = 64 - 59                   // normalization shift for q^5
	radixDNorm = radixD << radixShift      // normalized divisor, top bit set
)

// radixV is the Möller–Granlund reciprocal floor((2^128 - 1) / dNorm) - 2^64.
var radixV = func() uint64 {
	// floor((2^128-1)/d) - 2^64 = floor((2^128 - 1 - d*2^64) / d)
	//                           = floor(((^d) * 2^64 + (2^64 - 1)) / d)
	q, _ := bits.Div64(^radixDNorm, ^uint64(0), radixDNorm)
	return q
}()

// div2by1 returns (q, r) with q = floor((u1*2^64 + u0) / d) and r the
// remainder, for normalized d (top bit set), u1 < d, and v the reciprocal of d.
func div2by1(u1, u0, d, v uint64) (uint64, uint64) {
	qh, ql := bits.Mul64(v, u1)
	var c uint64
	ql, c = bits.Add64(ql, u0, 0)
	qh, _ = bits.Add64(qh, u1, c)
	qh++
	r := u0 - qh*d
	if r > ql {
		qh--
		r += d
	}
	if r >= d {
		qh++
		r -= d
	}
	return qh, r
}

// chunkValue returns sum_{j<m} t[j] * q^j for m <= 5 digits.
func chunkValue(t []uint16) uint64 {
	var v uint64
	for j := len(t) - 1; j >= 0; j-- {
		v = v*Q + uint64(t[j])
	}
	return v
}

// radixEncode writes r = sum_i coeffs[i] * q^i little-endian into dst
// (len(dst) == ThatLen). coeffs must have CoeffLen entries, each < q.
func radixEncode(dst []byte, coeffs []uint16) { radixEncodeN(dst[:ThatLen], coeffs) }

// radixDecode recovers the CoeffLen digits of the little-endian accumulator
// src (len(src) == ThatLen, unused high-order bits already cleared). It
// returns false if the accumulator is >= q^CoeffLen, i.e. not a valid
// encoding.
func radixDecode(coeffs []uint16, src []byte) bool {
	return radixDecodeN(coeffs[:CoeffLen], src[:ThatLen])
}

// radixEncodeN writes sum_i coeffs[i] * q^i little-endian into all of dst,
// for any number of digits whose value fits in len(dst) bytes.
func radixEncodeN(dst []byte, coeffs []uint16) {
	nl := (len(dst)+7)/8 + 1
	r := make([]uint64, nl)
	n := 0
	full := len(coeffs) / radixChunk
	if top := chunkValue(coeffs[full*radixChunk:]); top != 0 {
		r[0] = top
		n = 1
	}
	for c := full - 1; c >= 0; c-- {
		carry := chunkValue(coeffs[c*radixChunk : (c+1)*radixChunk])
		for i := 0; i < n; i++ {
			hi, lo := bits.Mul64(r[i], radixD)
			var cc uint64
			lo, cc = bits.Add64(lo, carry, 0)
			r[i] = lo
			carry = hi + cc
		}
		if carry != 0 {
			r[n] = carry
			n++
		}
	}
	buf := make([]byte, nl*8)
	for i := 0; i < nl; i++ {
		binary.LittleEndian.PutUint64(buf[8*i:], r[i])
	}
	copy(dst, buf[:len(dst)])
}

// radixDecodeN recovers len(coeffs) digits from the little-endian
// accumulator src. It returns false if the value is >= q^len(coeffs).
func radixDecodeN(coeffs []uint16, src []byte) bool {
	nl := (len(src) + 7) / 8
	buf := make([]byte, nl*8)
	copy(buf, src)

	// Limbs pre-shifted left by radixShift so the divisor is normalized.
	r := make([]uint64, nl+1)
	var prev uint64
	for i := 0; i < nl; i++ {
		w := binary.LittleEndian.Uint64(buf[8*i:])
		r[i] = w<<radixShift | prev>>(64-radixShift)
		prev = w
	}
	r[nl] = prev >> (64 - radixShift)
	n := nl + 1
	for n > 0 && r[n-1] == 0 {
		n--
	}

	full := len(coeffs) / radixChunk
	tail := len(coeffs) - full*radixChunk
	for c := 0; c < full; c++ {
		var rem uint64
		for i := n - 1; i >= 0; i-- {
			r[i], rem = div2by1(rem, r[i], radixDNorm, radixV)
		}
		var carry uint64
		for i := 0; i < n; i++ {
			w := r[i]
			r[i] = w<<radixShift | carry
			carry = w >> (64 - radixShift)
		}
		if carry != 0 {
			r[n] = carry
			n++
		}
		for n > 0 && r[n-1] == 0 {
			n--
		}
		rem >>= radixShift
		for j := 0; j < radixChunk; j++ {
			coeffs[c*radixChunk+j] = uint16(rem % Q)
			rem /= Q
		}
	}

	var top uint64
	switch {
	case n == 0:
	case n == 1:
		if r[0]&(1<<radixShift-1) != 0 {
			return false
		}
		top = r[0] >> radixShift
	default:
		return false
	}
	bound := uint64(1)
	for j := 0; j < tail; j++ {
		bound *= Q
	}
	if top >= bound {
		return false
	}
	for j := 0; j < tail; j++ {
		coeffs[full*radixChunk+j] = uint16(top % Q)
		top /= Q
	}
	return true
}
