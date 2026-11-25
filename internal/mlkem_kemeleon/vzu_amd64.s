#include "textflag.h"

// func vzeroupper()
//
// Clears the upper halves of the YMM registers. CIRCL's AVX2 ML-KEM and
// Keccak-x4 assembly (v1.5.0 through at least v1.6.5) returns without
// VZEROUPPER, leaving dirty upper state; the next legacy-SSE code -- notably
// Go's SHA-NI SHA-256 used by every HMAC in the handshake -- then pays the
// AVX-SSE transition penalty on every instruction.
TEXT ·vzeroupper(SB), NOSPLIT, $0-0
	VZEROUPPER
	RET
