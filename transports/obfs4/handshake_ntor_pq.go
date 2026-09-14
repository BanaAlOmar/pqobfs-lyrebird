//go:build pqobfs

/*
 * pq-obfs handshake: ML-KEM-768 + Kemeleon encoding replacement for the
 * classical Elligator 2 / X25519 ntor handshake, following the pq-obfs
 * construction of Günther, Stebila and Veitch (CCS 2024). Gated behind the
 * `pqobfs` build tag so the default build is unaffected.
 *
 * Message layout (all lengths in bytes; both messages are normalized to
 * LCOVER = 4096 bytes and followed by a 16-byte MAC):
 *
 *   ClientHello:  c_S' (1252) | ek' (1156) | M_C (16) | pad -> 4096 | MAC_C (16)
 *   ServerHello:  c_e' (1252) | AUTH (32) | M_S (16)  | pad -> 4096 | MAC_S (16)
 *
 * where
 *   c_S' = Kemeleon(ML-KEM.Encaps(pk_S)), the static encapsulation to the
 *          bridge's long-term ML-KEM-768 key, yielding K_S (known only to a
 *          holder of sk_S and to the client);
 *   ek'  = Kemeleon(ek_e), the client's ephemeral encapsulation key;
 *   c_e' = Kemeleon(ML-KEM.Encaps(ek_e)), yielding K_e (forward secrecy).
 *
 * Every transmitted field is a Kemeleon representative, so the whole
 * obfuscated KEM of [GSV24] is instantiated: each is computationally
 * indistinguishable from uniform bytes under module-LWE, and the marks and
 * MACs are pseudorandom under HMAC.
 *
 * Marks and MACs are keyed from K_S (strong obfuscation in the sense of
 * sObfKE: an observer who merely holds the bridge line cannot verify or
 * forge them). KEY_SEED and AUTH are derived from K_S || K_e and the full
 * transcript (c_S || ek' || c_e) under the protocol identifier, mirroring the
 * ntor key schedule with the two KEM secrets in place of xY and xB.
 *
 * This file lives in package obfs4 and reuses helpers from handshake_ntor.go
 * (markLength, macLength, getEpochHour, the Err* sentinels and InvalidMacError).
 */

package obfs4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash"
	"strconv"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

const (
	// pqClientMinHandshakeLength is the smallest meaningful client hello: the
	// encoded static-encapsulation ciphertext, the Kemeleon-encoded ephemeral
	// EK, the mark and the MAC.
	pqClientMinHandshakeLength = mlkem_kemeleon.EncodedCtLen + mlkem_kemeleon.EncodedLen +
		markLength + macLength // 1252+1156+16+16 = 2440

	// pqServerMinHandshakeLength is the smallest meaningful server hello: the
	// encoded ML-KEM ciphertext encapsulated to the client's ephemeral EK, the
	// AUTH tag, the mark and the MAC.
	pqServerMinHandshakeLength = mlkem_kemeleon.EncodedCtLen + pqAuthLength +
		markLength + macLength // 1252+32+16+16 = 1316

	// pqCoverLength is the fixed size every handshake message is normalized to
	// (before the trailing MAC).
	pqCoverLength = mlkem_kemeleon.LCOVER // 4096

	// pqHandshakeLength is the total wire length of a normalized handshake
	// message: cover bytes followed by the trailing MAC.
	pqHandshakeLength = pqCoverLength + macLength // 4112

	// pqAuthLength is the byte length of the ntor-style AUTH tag.
	pqAuthLength = sha256.Size // 32

	// pqMacKeyLength is the length of the HMAC key derived from K_S.
	pqMacKeyLength = sha256.Size // 32
)

// Field offsets inside the client hello cover region.
const (
	pqCliCtOff   = 0
	pqCliEKOff   = pqCliCtOff + mlkem_kemeleon.EncodedCtLen
	pqCliMarkOff = pqCliEKOff + mlkem_kemeleon.EncodedLen
)

// Field offsets inside the server hello cover region.
const (
	pqSrvCtOff   = 0
	pqSrvAuthOff = pqSrvCtOff + mlkem_kemeleon.EncodedCtLen
	pqSrvMarkOff = pqSrvAuthOff + pqAuthLength
)

// pq-obfs KDF protocol identifiers. These differ from the classical ntor
// identifiers so the two handshakes derive independent key material.
var (
	pqProtoID = []byte("pq-obfs-mlkem768-sha256-1")
	pqTKey    = append(append([]byte{}, pqProtoID...), []byte(":key_extract")...)
	pqTVerify = append(append([]byte{}, pqProtoID...), []byte(":key_verify")...)
	pqTMac    = append(append([]byte{}, pqProtoID...), []byte(":mac")...)
	pqTMacKey = append(append([]byte{}, pqProtoID...), []byte(":mac_key")...)
)

// pqMacKey derives the HMAC key for handshake marks and MACs from the static
// shared secret K_S and the node ID:
//
//	macKey = HMAC-SHA256(t_mac_key, K_S || NodeID)
//
// Because K_S is only obtainable by decapsulating c_S with sk_S, an observer
// who holds the bridge line (pk_S, NodeID) but not sk_S can neither verify nor
// forge the marks, which is what distinguishes the pq-obfs/st-obfs keying from
// the classical (B || NodeID) keying of obfs4.
func pqMacKey(staticSS []byte, nodeID *ntor.NodeID) []byte {
	h := hmac.New(sha256.New, pqTMacKey)
	h.Write(staticSS)
	h.Write(nodeID.Bytes()[:])
	return h.Sum(nil)[:pqMacKeyLength]
}

// pqNtorCommon derives KEY_SEED and AUTH from the two KEM shared secrets and
// the handshake transcript, preserving the ntor KDF structure:
//
//	secret_input = K_S || K_e || NodeID || c_S || ek' || c_e || ProtoID
//	KEY_SEED     = HMAC(t_key,    secret_input)
//	verify       = HMAC(t_verify, secret_input)
//	AUTH         = HMAC(t_mac,    verify || NodeID || ProtoID || "Server")
//
// K_S plays the role of xB (static authentication of the bridge), K_e the role
// of xY (forward secrecy); the transcript binding replaces X || Y || B.
// The transcript fields are the encoded forms as transmitted.
func pqNtorCommon(staticSS, ephSS []byte, id *ntor.NodeID, cS, encEK, cE []byte) (keySeed, auth []byte) {
	var secretInput bytes.Buffer
	secretInput.Write(staticSS)
	secretInput.Write(ephSS)
	secretInput.Write(id.Bytes()[:])
	secretInput.Write(cS)
	secretInput.Write(encEK)
	secretInput.Write(cE)
	secretInput.Write(pqProtoID)

	h := hmac.New(sha256.New, pqTKey)
	h.Write(secretInput.Bytes())
	keySeed = h.Sum(nil)

	h = hmac.New(sha256.New, pqTVerify)
	h.Write(secretInput.Bytes())
	verify := h.Sum(nil)

	h = hmac.New(sha256.New, pqTMac)
	h.Write(verify)
	h.Write(id.Bytes()[:])
	h.Write(pqProtoID)
	h.Write([]byte("Server"))
	auth = h.Sum(nil)
	return
}

// pqClientHandshake holds the state for the pq-obfs client handshake.
type pqClientHandshake struct {
	nodeID      *ntor.NodeID
	serverRawEK []byte // bridge's advertised static raw ML-KEM EK (1184 bytes), from the bridge line

	ephKP     *mlkem_kemeleon.KeyPair           // ephemeral keypair (dk retained for decapsulation)
	staticCt  *mlkem_kemeleon.EncodedCiphertext // c_S' and K_S
	encEK     []byte                            // Kemeleon-encoded ephemeral EK as sent
	epochHour []byte
	mac       hash.Hash

	serverMark []byte
}

func newPQClientHandshake(nodeID *ntor.NodeID, serverRawEK []byte) (*pqClientHandshake, error) {
	if len(serverRawEK) != mlkem_kemeleon.RawEKLen {
		return nil, fmt.Errorf("pq handshake: server EK must be %d bytes, got %d", mlkem_kemeleon.RawEKLen, len(serverRawEK))
	}
	return &pqClientHandshake{
		nodeID:      nodeID,
		serverRawEK: serverRawEK,
	}, nil
}

// generateHandshake produces the client hello:
//
//	[ c_S' (1252) | ek' (1156) | M_C (16) | random pad ] -> normalized to 4096 | MAC_C (16)
func (hs *pqClientHandshake) generateHandshake() ([]byte, error) {
	kp, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		return nil, err
	}
	// Encapsulate to the bridge's static key, retrying until the ciphertext
	// encodes under Kemeleon (acceptance ~0.77).
	sct, err := mlkem_kemeleon.EncapsulateEncoded(hs.serverRawEK)
	if err != nil {
		return nil, err
	}
	hs.ephKP = kp
	hs.staticCt = sct
	hs.encEK = kp.Representative() // 1156 bytes
	hs.mac = hmac.New(sha256.New, pqMacKey(sct.SharedSecret, hs.nodeID))

	var base bytes.Buffer
	base.Write(sct.Encoded) // c_S'
	base.Write(hs.encEK)    // ek'

	hs.mac.Reset()
	hs.mac.Write(base.Bytes())
	mark := hs.mac.Sum(nil)[:markLength]
	base.Write(mark)

	padded, err := mlkem_kemeleon.NormalizePadding(base.Bytes())
	if err != nil {
		return nil, err
	}

	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Reset()
	hs.mac.Write(padded)
	hs.mac.Write(hs.epochHour)
	mac := hs.mac.Sum(nil)[:macLength]

	return append(padded, mac...), nil
}

// parseServerHandshake validates the server hello, decapsulates the ML-KEM
// ciphertext to recover K_e, derives KEY_SEED/AUTH from both shared secrets
// and the transcript, verifies AUTH, and returns the derived KEY_SEED.
func (hs *pqClientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	if hs.ephKP == nil || hs.staticCt == nil {
		return 0, nil, ErrInvalidHandshake
	}
	if len(resp) < pqHandshakeLength {
		return 0, nil, ErrMarkNotFoundYet
	}
	if len(resp) > pqHandshakeLength {
		return 0, nil, ErrInvalidHandshake
	}

	// Fixed layout within the cover region: c_e' | AUTH | mark | pad...
	encCt := resp[pqSrvCtOff : pqSrvCtOff+mlkem_kemeleon.EncodedCtLen]
	serverAuth := resp[pqSrvAuthOff : pqSrvAuthOff+pqAuthLength]
	markRx := resp[pqSrvMarkOff : pqSrvMarkOff+markLength]

	// Mark over (c_e' | AUTH), keyed from K_S.
	hs.mac.Reset()
	hs.mac.Write(resp[:pqSrvMarkOff])
	hs.serverMark = hs.mac.Sum(nil)[:markLength]
	if !hmac.Equal(markRx, hs.serverMark) {
		return 0, nil, ErrInvalidHandshake
	}

	// MAC_S covers the cover region plus the epoch hour.
	hs.mac.Reset()
	hs.mac.Write(resp[:pqCoverLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pqCoverLength:pqHandshakeLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	ct, err := mlkem_kemeleon.DecodeCiphertext(encCt)
	if err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decode ciphertext: %w", err)
	}
	ephSS, err := hs.ephKP.Decapsulate(ct)
	if err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decapsulate: %w", err)
	}

	keySeed, auth := pqNtorCommon(hs.staticCt.SharedSecret, ephSS, hs.nodeID,
		hs.staticCt.Encoded, hs.encEK, encCt)
	if !hmac.Equal(auth, serverAuth) {
		return 0, nil, ErrNtorFailed
	}
	return pqHandshakeLength, keySeed, nil
}

// pqServerHandshake holds the state for the pq-obfs server handshake.
type pqServerHandshake struct {
	nodeID   *ntor.NodeID
	staticKP *mlkem_kemeleon.KeyPair // bridge's long-term ML-KEM-768 keypair (sk_S, pk_S)

	epochHour  []byte
	mac        hash.Hash
	serverAuth []byte
	ctToClient []byte // c_e', the encoded encapsulation to the client's ephemeral EK
}

func newPQServerHandshake(nodeID *ntor.NodeID, staticKP *mlkem_kemeleon.KeyPair) *pqServerHandshake {
	return &pqServerHandshake{
		nodeID:   nodeID,
		staticKP: staticKP,
	}
}

// parseClientHandshake decapsulates c_S with sk_S to obtain K_S, derives the
// mark/MAC key from it, validates the hello (mark, MAC with epoch tolerance,
// replay filter), decodes the client's ephemeral EK, encapsulates to it, and
// derives KEY_SEED/AUTH. It returns KEY_SEED.
//
// Every failure path returns before any response is generated, so a probe
// that does not carry a valid c_S/mark/MAC is met with silence, as in obfs4.
func (hs *pqServerHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	if len(resp) < pqHandshakeLength {
		return nil, ErrMarkNotFoundYet
	}
	if len(resp) > pqHandshakeLength {
		return nil, ErrInvalidHandshake
	}

	encCS := resp[pqCliCtOff : pqCliCtOff+mlkem_kemeleon.EncodedCtLen]
	clientEncEK := resp[pqCliEKOff : pqCliEKOff+mlkem_kemeleon.EncodedLen]
	markRx := resp[pqCliMarkOff : pqCliMarkOff+markLength]

	// K_S <- Decaps(sk_S, Kemeleon^-1(c_S')). Every 1252-byte string decodes,
	// and ML-KEM decapsulation is implicit-rejection, so a garbage c_S' yields
	// a pseudorandom K_S and the mark check below fails without revealing
	// which step went wrong.
	cS, err := mlkem_kemeleon.DecodeCiphertext(encCS)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	staticSS, err := hs.staticKP.Decapsulate(cS)
	if err != nil {
		return nil, ErrInvalidHandshake
	}
	hs.mac = hmac.New(sha256.New, pqMacKey(staticSS, hs.nodeID))

	hs.mac.Reset()
	hs.mac.Write(resp[:pqCliMarkOff]) // c_S' | ek'
	clientMark := hs.mac.Sum(nil)[:markLength]
	if !hmac.Equal(markRx, clientMark) {
		return nil, ErrInvalidHandshake
	}

	// Validate MAC_C, allowing the epoch to be off by up to an hour either way.
	macRx := resp[pqCoverLength:pqHandshakeLength]
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		epochHour := []byte(strconv.FormatInt(getEpochHour()+off, 10))
		hs.mac.Reset()
		hs.mac.Write(resp[:pqCoverLength])
		hs.mac.Write(epochHour)
		macCmp := hs.mac.Sum(nil)[:macLength]
		if hmac.Equal(macCmp, macRx) {
			if filter.TestAndSet(time.Now(), macRx) {
				return nil, ErrReplayedHandshake
			}
			macFound = true
			hs.epochHour = epochHour
		}
	}
	if !macFound {
		return nil, ErrInvalidHandshake
	}

	clientRawEK, err := mlkem_kemeleon.DecodeEK(clientEncEK)
	if err != nil {
		return nil, fmt.Errorf("pq handshake: decode client EK: %w", err)
	}
	ect, err := mlkem_kemeleon.EncapsulateEncoded(clientRawEK)
	if err != nil {
		return nil, fmt.Errorf("pq handshake: encapsulate to client EK: %w", err)
	}
	hs.ctToClient = ect.Encoded

	keySeed, auth := pqNtorCommon(staticSS, ect.SharedSecret, hs.nodeID,
		encCS, clientEncEK, ect.Encoded)
	hs.serverAuth = auth
	return keySeed, nil
}

// generateHandshake produces the server hello:
//
//	[ c_e' (1252) | AUTH (32) | M_S (16) | pad ] -> 4096 | MAC_S (16)
//
// parseClientHandshake MUST have run first (it sets ctToClient, serverAuth,
// epochHour and the K_S-keyed MAC).
func (hs *pqServerHandshake) generateHandshake() ([]byte, error) {
	if hs.ctToClient == nil || hs.serverAuth == nil || hs.mac == nil {
		return nil, ErrInvalidHandshake
	}

	var base bytes.Buffer
	base.Write(hs.ctToClient)
	base.Write(hs.serverAuth)

	hs.mac.Reset()
	hs.mac.Write(base.Bytes())
	mark := hs.mac.Sum(nil)[:markLength]
	base.Write(mark)

	padded, err := mlkem_kemeleon.NormalizePadding(base.Bytes())
	if err != nil {
		return nil, err
	}

	hs.mac.Reset()
	hs.mac.Write(padded)
	hs.mac.Write(hs.epochHour)
	mac := hs.mac.Sum(nil)[:macLength]

	return append(padded, mac...), nil
}
