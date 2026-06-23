//go:build pqobfs

/*
 * pq-obfs handshake: ML-KEM-768 + Kemeleon encoding replacement for the
 * classical Elligator 2 / X25519 ntor handshake. Gated behind the `pqobfs`
 * build tag so the default build is unaffected.
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
	// Kemeleon-encoded ephemeral EK plus mark plus MAC.
	pqClientMinHandshakeLength = mlkem_kemeleon.EncodedLen + markLength + macLength // 1156+16+16 = 1188

	// pqServerMinHandshakeLength is the smallest meaningful server hello: the
	// Kemeleon-encoded ephemeral EK, the ML-KEM ciphertext encapsulated to the
	// client, the AUTH tag, mark and MAC.
	pqServerMinHandshakeLength = mlkem_kemeleon.EncodedLen + mlkem_kemeleon.CiphertextLen +
		pqAuthLength + markLength + macLength // 1156+1088+32+16+16 = 2308

	// pqCoverLength is the fixed size every handshake message is normalized to
	// (before the trailing MAC).
	pqCoverLength = mlkem_kemeleon.LCOVER // 4096

	// pqHandshakeLength is the total wire length of a normalized handshake
	// message: cover bytes followed by the trailing MAC.
	pqHandshakeLength = pqCoverLength + macLength // 4112

	// pqAuthLength is the byte length of the ntor-style AUTH tag.
	pqAuthLength = sha256.Size // 32
)

// pq-obfs KDF protocol identifiers. These differ from the classical ntor
// identifiers so the two handshakes derive independent key material.
var (
	pqProtoID = []byte("pq-obfs-mlkem768-sha256-1")
	pqTKey    = append(append([]byte{}, pqProtoID...), []byte(":key_extract")...)
	pqTVerify = append(append([]byte{}, pqProtoID...), []byte(":key_verify")...)
	pqTMac    = append(append([]byte{}, pqProtoID...), []byte(":mac")...)
)

// pqMacKey builds the HMAC key for handshake marks/MACs: the first 32 bytes of
// the server's advertised static EK concatenated with the node ID. This mirrors
// the classical handshake's (serverIdentity || nodeID) keying.
func pqMacKey(serverRawEK []byte, nodeID *ntor.NodeID) []byte {
	key := make([]byte, 0, 32+ntor.NodeIDLength)
	key = append(key, serverRawEK[:32]...)
	key = append(key, nodeID.Bytes()[:]...)
	return key
}

// pqNtorCommon derives KEY_SEED and AUTH from the KEM shared secret, preserving
// the ntor KDF structure with KEM in place of Diffie-Hellman.
func pqNtorCommon(ss []byte, id *ntor.NodeID) (keySeed, auth []byte) {
	h := hmac.New(sha256.New, pqTKey)
	h.Write(ss)
	h.Write(id.Bytes()[:])
	keySeed = h.Sum(nil)

	h = hmac.New(sha256.New, pqTVerify)
	h.Write(ss)
	h.Write(id.Bytes()[:])
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
	ephKP       *mlkem_kemeleon.KeyPair // client ephemeral keypair
	nodeID      *ntor.NodeID
	serverRawEK []byte // server's advertised static raw ML-KEM EK (1184 bytes)
	epochHour   []byte
	mac         hash.Hash

	serverMark []byte
}

func newPQClientHandshake(nodeID *ntor.NodeID, serverRawEK []byte) (*pqClientHandshake, error) {
	if len(serverRawEK) != mlkem_kemeleon.RawEKLen {
		return nil, fmt.Errorf("pq handshake: server EK must be %d bytes, got %d", mlkem_kemeleon.RawEKLen, len(serverRawEK))
	}
	hs := &pqClientHandshake{
		nodeID:      nodeID,
		serverRawEK: serverRawEK,
	}
	hs.mac = hmac.New(sha256.New, pqMacKey(serverRawEK, nodeID))
	return hs, nil
}

// generateHandshake produces the client hello:
//
//	[ enc_eph_pk (1156) | M_C (16) | random pad ] -> normalized to 4096 | MAC_C (16)
func (hs *pqClientHandshake) generateHandshake() ([]byte, error) {
	kp, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		return nil, err
	}
	hs.ephKP = kp
	encEphPK := kp.Representative() // 1156 bytes

	hs.mac.Reset()
	hs.mac.Write(encEphPK)
	mark := hs.mac.Sum(nil)[:markLength]

	var base bytes.Buffer
	base.Write(encEphPK)
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
// ciphertext to recover the shared secret, verifies AUTH, and returns the
// derived KEY_SEED.
func (hs *pqClientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	if len(resp) < pqHandshakeLength {
		return 0, nil, ErrMarkNotFoundYet
	}
	if len(resp) > pqHandshakeLength {
		return 0, nil, ErrInvalidHandshake
	}

	// Fixed layout within the cover region:
	//   enc_resp_pk | ct_to_client | AUTH | mark | pad...
	off := 0
	serverEncEK := resp[off : off+mlkem_kemeleon.EncodedLen]
	off += mlkem_kemeleon.EncodedLen
	ct := resp[off : off+mlkem_kemeleon.CiphertextLen]
	off += mlkem_kemeleon.CiphertextLen
	serverAuth := resp[off : off+pqAuthLength]
	off += pqAuthLength
	markRx := resp[off : off+markLength]

	// Derive and check the mark over (enc_resp_pk | ct | AUTH).
	hs.mac.Reset()
	hs.mac.Write(resp[:mlkem_kemeleon.EncodedLen+mlkem_kemeleon.CiphertextLen+pqAuthLength])
	hs.serverMark = hs.mac.Sum(nil)[:markLength]
	if !hmac.Equal(markRx, hs.serverMark) {
		return 0, nil, ErrInvalidHandshake
	}

	// MAC_C/MAC_S is the trailing macLength bytes; it covers the cover region
	// (everything but the trailing MAC) plus the epoch hour.
	hs.mac.Reset()
	hs.mac.Write(resp[:pqCoverLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pqCoverLength:pqHandshakeLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	// The server ephemeral EK is decoded only to keep the wire format honest;
	// the shared secret comes from decapsulating the ciphertext the server
	// encapsulated to our ephemeral key.
	if _, err := mlkem_kemeleon.DecodeEK(serverEncEK); err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decode server EK: %w", err)
	}
	ss, err := hs.ephKP.Decapsulate(ct)
	if err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decapsulate: %w", err)
	}

	keySeed, auth := pqNtorCommon(ss, hs.nodeID)
	if !hmac.Equal(auth, serverAuth) {
		return 0, nil, ErrNtorFailed
	}
	return pqHandshakeLength, keySeed, nil
}

// pqServerHandshake holds the state for the pq-obfs server handshake.
type pqServerHandshake struct {
	nodeID      *ntor.NodeID
	serverRawEK []byte
	mac         hash.Hash
	epochHour   []byte
	serverAuth  []byte

	ctToClient []byte // ML-KEM ciphertext encapsulated to the client's ephemeral EK
}

func newPQServerHandshake(nodeID *ntor.NodeID, serverRawEK []byte) *pqServerHandshake {
	hs := &pqServerHandshake{
		nodeID:      nodeID,
		serverRawEK: serverRawEK,
	}
	hs.mac = hmac.New(sha256.New, pqMacKey(serverRawEK, nodeID))
	return hs
}

// parseClientHandshake validates the client hello, encapsulates to the client's
// ephemeral EK (producing both the ciphertext to return and the shared secret),
// derives KEY_SEED/AUTH, and returns KEY_SEED.
func (hs *pqServerHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	if len(resp) < pqHandshakeLength {
		return nil, ErrMarkNotFoundYet
	}
	if len(resp) > pqHandshakeLength {
		return nil, ErrInvalidHandshake
	}

	clientEncEK := resp[:mlkem_kemeleon.EncodedLen]
	markRx := resp[mlkem_kemeleon.EncodedLen : mlkem_kemeleon.EncodedLen+markLength]

	hs.mac.Reset()
	hs.mac.Write(clientEncEK)
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
	ct, ss, err := mlkem_kemeleon.Encapsulate(clientRawEK)
	if err != nil {
		return nil, fmt.Errorf("pq handshake: encapsulate to client EK: %w", err)
	}
	hs.ctToClient = ct

	keySeed, auth := pqNtorCommon(ss, hs.nodeID)
	hs.serverAuth = auth
	return keySeed, nil
}

// generateHandshake produces the server hello:
//
//	[ enc_resp_pk (1156) | ct_to_client (1088) | AUTH (32) | M_S (16) | pad ] -> 4096 | MAC_S (16)
//
// parseClientHandshake MUST have run first (it sets ctToClient, serverAuth and epochHour).
func (hs *pqServerHandshake) generateHandshake() ([]byte, error) {
	if hs.ctToClient == nil || hs.serverAuth == nil {
		return nil, ErrInvalidHandshake
	}
	kp, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		return nil, err
	}
	encEphPK := kp.Representative()

	var base bytes.Buffer
	base.Write(encEphPK)
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
