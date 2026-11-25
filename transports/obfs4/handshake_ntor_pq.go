//go:build pqobfs

/*
 * pq-obfs handshake: ML-KEM-768 + Kemeleon encoding replacement for the
 * classical Elligator 2 / X25519 ntor handshake, following the pq-obfs
 * construction of Günther, Stebila and Veitch (CCS 2024). Gated behind the
 * `pqobfs` build tag so the default build is unaffected.
 *
 * Message layout (all lengths in bytes). As in obfs4, the random pad precedes
 * the mark, and the receiver locates the mark by searching for it, so the
 * total length of each message is a free parameter chosen by a cover policy
 * (pqCoverPolicy): a fixed length, or a length drawn per message.
 *
 *   ClientHello:  c_S' | ek' [| X'] | P_C | M_C (16) | MAC_C (16)
 *   ServerHello:  c_e' [| Y'] | AUTH (32) | P_S | M_S (16) | MAC_S (16)
 *
 * A suite (pqSuite) selects the Kemeleon encoding -- rejection sampling
 * (c' 1,252 B, ek' 1,156 B) or the non-rejecting default encoding (1,536 B,
 * 1,184 B) -- and whether the exchange is hybrid: with hybrid set, X' and Y'
 * are 32-byte Elligator 2 representatives of ephemeral X25519 keys, the
 * bridge also holds a static X25519 key B, and both Diffie-Hellman values
 * enter the key schedule beside the two KEM secrets.
 *
 * The transport appends obfs4's inline PRNG-seed frame to the server hello in
 * the same write; the server policy length includes it, so under the fixed
 * policy both first flights are exactly pqHandshakeLength bytes on the wire.
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

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
	"golang.org/x/crypto/curve25519"
)

const (
	// pqClientKeyMaterialLength is c_S' | ek' for the default suite
	// (rejection-sampling encoding, not hybrid).
	pqClientKeyMaterialLength = mlkem_kemeleon.EncodedCtLen + mlkem_kemeleon.EncodedLen // 2408

	// pqServerKeyMaterialLength is c_e' | AUTH for the default suite.
	pqServerKeyMaterialLength = mlkem_kemeleon.EncodedCtLen + pqAuthLength // 1284

	// pqClientMinHandshakeLength / pqServerMinHandshakeLength: smallest
	// hellos of the default suite (no padding).
	pqClientMinHandshakeLength = pqClientKeyMaterialLength + markLength + macLength // 2440
	pqServerMinHandshakeLength = pqServerKeyMaterialLength + markLength + macLength // 1316

	// ML-KEM-1024 minima of the default suite, used as floors by the
	// "hide parameter set" policy.
	pqClientMinHandshakeLength1024 = 1658 + 1530 + markLength + macLength         // 3220
	pqServerMinHandshakeLength1024 = 1658 + pqAuthLength + markLength + macLength // 1722

	// pqCoverLength is the fixed-policy cover length before the trailing MAC.
	pqCoverLength = mlkem_kemeleon.LCOVER // 4096

	// pqHandshakeLength is the fixed-policy first-flight length on the wire.
	pqHandshakeLength = pqCoverLength + macLength // 4112

	pqAuthLength   = sha256.Size // 32
	pqMacKeyLength = sha256.Size // 32
	pqDHLength     = 32
)

// pqSuite selects the encoding and whether the handshake is hybrid.
type pqSuite struct {
	defaultEnc bool // non-rejecting Kemeleon encoding
	hybrid     bool // add X25519/Elligator 2 alongside ML-KEM
}

func (s pqSuite) ctLen() int {
	if s.defaultEnc {
		return mlkem_kemeleon.DefaultCtLen
	}
	return mlkem_kemeleon.EncodedCtLen
}

func (s pqSuite) ekLen() int {
	if s.defaultEnc {
		return mlkem_kemeleon.DefaultEKLen
	}
	return mlkem_kemeleon.EncodedLen
}

func (s pqSuite) dhLen() int {
	if s.hybrid {
		return pqDHLength
	}
	return 0
}

// clientKM is the length of the fixed-offset prefix c_S' | ek' [| X'].
func (s pqSuite) clientKM() int { return s.ctLen() + s.ekLen() + s.dhLen() }

// serverKM is the length of the fixed-offset prefix c_e' [| Y'] | AUTH.
func (s pqSuite) serverKM() int { return s.ctLen() + s.dhLen() + pqAuthLength }

func (s pqSuite) clientMin() int { return s.clientKM() + markLength + macLength }
func (s pqSuite) serverMin() int { return s.serverKM() + markLength + macLength }

// Minima of the same suite instantiated with ML-KEM-1024 (rejection: c' 1,658
// and ek' 1,530 B; default: 5 x 384 and 4 x 384 + 32 B).
func (s pqSuite) clientMin1024() int {
	ct, ek := 1658, 1530
	if s.defaultEnc {
		ct, ek = 1920, 1568
	}
	return ct + ek + s.dhLen() + markLength + macLength
}

func (s pqSuite) serverMin1024() int {
	ct := 1658
	if s.defaultEnc {
		ct = 1920
	}
	return ct + s.dhLen() + pqAuthLength + markLength + macLength
}

// protoID names the suite in the key schedule, so suites never share keys.
func (s pqSuite) protoID() []byte {
	id := "pq-obfs-"
	if s.hybrid {
		id += "x25519"
	}
	id += "mlkem768"
	if s.defaultEnc {
		id += "d"
	}
	return []byte(id + "-sha256-1")
}

func (s pqSuite) generateKeyPair() (*mlkem_kemeleon.KeyPair, error) {
	if s.defaultEnc {
		return mlkem_kemeleon.GenerateKeyPairDefault(nil)
	}
	return mlkem_kemeleon.GenerateKeyPair(nil)
}

func (s pqSuite) encapsulate(rawEK []byte) (*mlkem_kemeleon.EncodedCiphertext, error) {
	if s.defaultEnc {
		return mlkem_kemeleon.EncapsulateEncodedDefault(rawEK)
	}
	return mlkem_kemeleon.EncapsulateEncoded(rawEK)
}

func (s pqSuite) decodeCt(b []byte) ([]byte, error) {
	if s.defaultEnc {
		return mlkem_kemeleon.DecodeCtDefault(b)
	}
	return mlkem_kemeleon.DecodeCiphertext(b)
}

func (s pqSuite) decodeEK(b []byte) ([]byte, error) {
	if s.defaultEnc {
		return mlkem_kemeleon.DecodeEKDefault(b)
	}
	return mlkem_kemeleon.DecodeEK(b)
}

// x25519 computes a Diffie-Hellman value and rejects low-order results.
func x25519(priv *ntor.PrivateKey, pub *ntor.PublicKey) ([]byte, error) {
	return curve25519.X25519(priv.Bytes()[:], pub.Bytes()[:])
}

// Cover-policy kinds.
const (
	pqCoverFixed = iota
	pqCoverUniform
)

// pqCoverPolicy decides the total on-the-wire length of each handshake
// message. Lengths include the trailing MAC and, for the server, the
// transport's inline seed frame (trailerLen).
type pqCoverPolicy struct {
	kind       int
	fixedLen   int
	hideParams bool // floors are the suite's ML-KEM-1024 minima
}

// pqFixedCover is the fixed-length policy (4,112 B both ways).
func pqFixedCover() pqCoverPolicy {
	return pqCoverPolicy{kind: pqCoverFixed, fixedLen: pqHandshakeLength}
}

// pqUniformCover draws lengths uniformly from [suite minimum, 8192]; with
// hideParams the floors are the ML-KEM-1024 minima of the same suite.
func pqUniformCover(hideParams bool) pqCoverPolicy {
	return pqCoverPolicy{kind: pqCoverUniform, hideParams: hideParams}
}

func (p pqCoverPolicy) clientFloor(s pqSuite) int {
	if p.hideParams {
		return s.clientMin1024()
	}
	return s.clientMin()
}

func (p pqCoverPolicy) serverFloor(s pqSuite) int {
	if p.hideParams {
		return s.serverMin1024()
	}
	return s.serverMin()
}

// clientLength returns the total client-hello length for one message.
func (p pqCoverPolicy) clientLength(s pqSuite) int {
	if p.kind == pqCoverFixed {
		return p.fixedLen
	}
	return csrand.IntRange(p.clientFloor(s), maxHandshakeLength)
}

// serverLength returns the total server first-flight length, including a
// trailer of trailerLen bytes appended by the transport.
func (p pqCoverPolicy) serverLength(s pqSuite, trailerLen int) int {
	if p.kind == pqCoverFixed {
		return p.fixedLen
	}
	return csrand.IntRange(p.serverFloor(s)+trailerLen, maxHandshakeLength)
}

func pqLabel(s pqSuite, suffix string) []byte {
	return append(append([]byte{}, s.protoID()...), []byte(suffix)...)
}

// pqMacKey derives the HMAC key for handshake marks and MACs from the static
// secret (K_S, or K_S || DH(x, B) in a hybrid suite) and the node ID:
//
//	macKey = HMAC-SHA256(t_mac_key, static || NodeID)
//
// Only a holder of sk_S (and, if hybrid, b) can compute it, so an observer
// who holds the bridge line can neither verify nor forge marks (sObfKE).
func pqMacKey(s pqSuite, static []byte, nodeID *ntor.NodeID) []byte {
	h := hmac.New(sha256.New, pqLabel(s, ":mac_key"))
	h.Write(static)
	h.Write(nodeID.Bytes()[:])
	return h.Sum(nil)[:pqMacKeyLength]
}

// pqNtorCommon derives KEY_SEED and AUTH, preserving the ntor KDF structure:
//
//	secret_input = static || ephemeral || NodeID || clientKM || serverKM' || ProtoID
//	KEY_SEED     = HMAC(t_key,    secret_input)
//	verify       = HMAC(t_verify, secret_input)
//	AUTH         = HMAC(t_mac,    verify || NodeID || ProtoID || "Server")
//
// static is K_S (|| DH(x,B)), ephemeral is K_e (|| DH(x,Y)); clientKM is
// c_S' | ek' (| X') and serverKM' is c_e' (| Y'), the encoded wire bytes. For
// the default suite this is K_S || K_e || NodeID || c_S' || ek' || c_e' || PID.
func pqNtorCommon(s pqSuite, static, eph []byte, id *ntor.NodeID, clientKM, serverKM []byte) (keySeed, auth []byte) {
	var in bytes.Buffer
	in.Write(static)
	in.Write(eph)
	in.Write(id.Bytes()[:])
	in.Write(clientKM)
	in.Write(serverKM)
	in.Write(s.protoID())

	h := hmac.New(sha256.New, pqLabel(s, ":key_extract"))
	h.Write(in.Bytes())
	keySeed = h.Sum(nil)

	h = hmac.New(sha256.New, pqLabel(s, ":key_verify"))
	h.Write(in.Bytes())
	verify := h.Sum(nil)

	h = hmac.New(sha256.New, pqLabel(s, ":mac"))
	h.Write(verify)
	h.Write(id.Bytes()[:])
	h.Write(s.protoID())
	h.Write([]byte("Server"))
	auth = h.Sum(nil)
	return
}

// pqBridgeKey is one long-term bridge identity: an ML-KEM-768 key pair and,
// for hybrid suites, an X25519 key pair.
type pqBridgeKey struct {
	kem *mlkem_kemeleon.KeyPair
	dh  *ntor.Keypair // nil unless hybrid
}

// pqClientKeyMaterial is the client's per-connection key material. It is
// generated before the TCP connection is opened (see pqobfs.go) so that the
// rejection-sampling retries of Kemeleon and Elligator never fall between
// the TCP handshake and the first payload.
type pqClientKeyMaterial struct {
	ephKP    *mlkem_kemeleon.KeyPair
	staticCt *mlkem_kemeleon.EncodedCiphertext
	dh       *ntor.Keypair // hybrid only
}

func newPQClientKeyMaterial(s pqSuite, serverRawEK []byte) (*pqClientKeyMaterial, error) {
	kp, err := s.generateKeyPair()
	if err != nil {
		return nil, err
	}
	sct, err := s.encapsulate(serverRawEK)
	if err != nil {
		return nil, err
	}
	km := &pqClientKeyMaterial{ephKP: kp, staticCt: sct}
	if s.hybrid {
		if km.dh, err = ntor.NewKeypair(true); err != nil {
			return nil, err
		}
	}
	return km, nil
}

// pqClientHandshake holds the state for the pq-obfs client handshake.
type pqClientHandshake struct {
	suite       pqSuite
	nodeID      *ntor.NodeID
	serverRawEK []byte          // bridge's static ML-KEM key (1184 bytes)
	serverDH    *ntor.PublicKey // bridge's static X25519 key (hybrid)
	policy      pqCoverPolicy

	km        *pqClientKeyMaterial
	clientKM  []byte // c_S' | ek' [| X'] as sent
	static    []byte // K_S [|| DH(x, B)]
	epochHour []byte
	mac       hash.Hash

	serverMark []byte
}

func newPQClientHandshake(nodeID *ntor.NodeID, serverRawEK []byte) (*pqClientHandshake, error) {
	return newPQClientHandshakeWithPolicy(nodeID, serverRawEK, pqFixedCover(), nil)
}

func newPQClientHandshakeWithPolicy(nodeID *ntor.NodeID, serverRawEK []byte, policy pqCoverPolicy,
	km *pqClientKeyMaterial) (*pqClientHandshake, error) {
	return newPQClientHandshakeSuite(pqSuite{}, nodeID, serverRawEK, nil, policy, km)
}

func newPQClientHandshakeSuite(s pqSuite, nodeID *ntor.NodeID, serverRawEK []byte, serverDH *ntor.PublicKey,
	policy pqCoverPolicy, km *pqClientKeyMaterial) (*pqClientHandshake, error) {
	if len(serverRawEK) != mlkem_kemeleon.RawEKLen {
		return nil, fmt.Errorf("pq handshake: server EK must be %d bytes, got %d", mlkem_kemeleon.RawEKLen, len(serverRawEK))
	}
	if s.hybrid && serverDH == nil {
		return nil, fmt.Errorf("pq handshake: hybrid suite needs the bridge's X25519 key")
	}
	return &pqClientHandshake{suite: s, nodeID: nodeID, serverRawEK: serverRawEK, serverDH: serverDH,
		policy: policy, km: km}, nil
}

// generateHandshake produces the client hello
//
//	c_S' | ek' [| X'] | P_C | M_C (16) | MAC_C (16)
//
// with |P_C| chosen so the total matches the cover policy.
func (hs *pqClientHandshake) generateHandshake() ([]byte, error) {
	s := hs.suite
	if hs.km == nil {
		km, err := newPQClientKeyMaterial(s, hs.serverRawEK)
		if err != nil {
			return nil, err
		}
		hs.km = km
	}
	total := hs.policy.clientLength(s)
	if total < s.clientMin() || total > maxHandshakeLength {
		return nil, fmt.Errorf("pq handshake: client length %d outside [%d, %d]",
			total, s.clientMin(), maxHandshakeLength)
	}

	var km bytes.Buffer
	km.Write(hs.km.staticCt.Encoded)       // c_S'
	km.Write(hs.km.ephKP.Representative()) // ek'
	hs.static = append([]byte{}, hs.km.staticCt.SharedSecret...)
	if s.hybrid {
		km.Write(hs.km.dh.Representative().Bytes()[:]) // X'
		xB, err := x25519(hs.km.dh.Private(), hs.serverDH)
		if err != nil {
			return nil, err
		}
		hs.static = append(hs.static, xB...)
	}
	hs.clientKM = km.Bytes()
	hs.mac = hmac.New(sha256.New, pqMacKey(s, hs.static, hs.nodeID))

	hs.mac.Reset()
	hs.mac.Write(hs.clientKM)
	mark := hs.mac.Sum(nil)[:markLength]

	var buf bytes.Buffer
	buf.Write(hs.clientKM)
	pad := make([]byte, total-s.clientMin())
	if err := csrand.Bytes(pad); err != nil {
		return nil, err
	}
	buf.Write(pad)
	buf.Write(mark)

	hs.epochHour = []byte(strconv.FormatInt(getEpochHour(), 10))
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil)[:macLength])
	return buf.Bytes(), nil
}

// parseServerHandshake validates the server hello and returns the number of
// bytes consumed and KEY_SEED. Data after MAC_S (the seed frame) is left in
// the buffer for the caller.
func (hs *pqClientHandshake) parseServerHandshake(resp []byte) (int, []byte, error) {
	s := hs.suite
	if hs.km == nil || hs.mac == nil {
		return 0, nil, ErrInvalidHandshake
	}
	if len(resp) < s.serverMin() {
		return 0, nil, ErrMarkNotFoundYet
	}
	ctLen, dhLen := s.ctLen(), s.dhLen()
	encCt := resp[:ctLen]
	serverEph := resp[:ctLen+dhLen] // c_e' [| Y']
	serverAuth := resp[ctLen+dhLen : s.serverKM()]

	if hs.serverMark == nil {
		hs.mac.Reset()
		hs.mac.Write(resp[:s.serverKM()])
		hs.serverMark = hs.mac.Sum(nil)[:markLength]
	}
	pos := findMarkMac(hs.serverMark, resp, s.serverKM(), maxHandshakeLength, false)
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return 0, nil, ErrInvalidHandshake
		}
		return 0, nil, ErrMarkNotFoundYet
	}

	hs.mac.Reset()
	hs.mac.Write(resp[:pos+markLength])
	hs.mac.Write(hs.epochHour)
	macCmp := hs.mac.Sum(nil)[:macLength]
	macRx := resp[pos+markLength : pos+markLength+macLength]
	if !hmac.Equal(macCmp, macRx) {
		return 0, nil, &InvalidMacError{macCmp, macRx}
	}

	ct, err := s.decodeCt(encCt)
	if err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decode ciphertext: %w", err)
	}
	eph, err := hs.km.ephKP.Decapsulate(ct)
	if err != nil {
		return 0, nil, fmt.Errorf("pq handshake: decapsulate: %w", err)
	}
	if s.hybrid {
		var rep ntor.Representative
		copy(rep[:], resp[ctLen:ctLen+dhLen])
		xY, err := x25519(hs.km.dh.Private(), rep.ToPublic())
		if err != nil {
			return 0, nil, ErrNtorFailed
		}
		eph = append(eph, xY...)
	}

	keySeed, auth := pqNtorCommon(s, hs.static, eph, hs.nodeID, hs.clientKM, serverEph)
	if !hmac.Equal(auth, serverAuth) {
		return 0, nil, ErrNtorFailed
	}
	return pos + markLength + macLength, keySeed, nil
}

// pqServerHandshake holds the state for the pq-obfs server handshake.
type pqServerHandshake struct {
	suite  pqSuite
	nodeID *ntor.NodeID
	keys   []pqBridgeKey // current key first; older keys during rotation
	eph    *ntor.Keypair // bridge ephemeral X25519 (hybrid), made before reading
	policy pqCoverPolicy

	// trailerLen is the number of bytes the transport appends after MAC_S in
	// the same write (obfs4's inline PRNG-seed frame).
	trailerLen int

	cands      []pqServerCandidate
	static     []byte
	epochHour  []byte
	mac        hash.Hash
	serverAuth []byte
	serverEph  []byte // c_e' [| Y']
}

// pqServerCandidate is the mark state derived under one bridge key.
type pqServerCandidate struct {
	static []byte
	mac    hash.Hash
	mark   []byte
}

func newPQServerHandshake(nodeID *ntor.NodeID, staticKP *mlkem_kemeleon.KeyPair) *pqServerHandshake {
	return &pqServerHandshake{nodeID: nodeID, keys: []pqBridgeKey{{kem: staticKP}}, policy: pqFixedCover()}
}

// parseClientHandshake is called each time more client data arrives. Once
// the fixed-offset key material is present it decapsulates c_S under every
// bridge key (once), derives a mark per key, then looks for one of the marks
// at the tail of the buffer, verifies MAC_C (epoch tolerance, replay
// filter), decodes ek', encapsulates to it and derives KEY_SEED/AUTH.
//
// With one bridge key this does exactly one decapsulation. During a key
// rotation every connection pays one decapsulation per key, whichever key it
// uses, so the work does not reveal which key a client holds.
func (hs *pqServerHandshake) parseClientHandshake(filter *replayfilter.ReplayFilter, resp []byte) ([]byte, error) {
	s := hs.suite
	if len(resp) < s.clientMin() {
		return nil, ErrMarkNotFoundYet
	}
	ctLen, ekLen, dhLen := s.ctLen(), s.ekLen(), s.dhLen()
	encCS := resp[:ctLen]
	clientEncEK := resp[ctLen : ctLen+ekLen]
	clientKM := resp[:s.clientKM()]

	if hs.cands == nil {
		var X *ntor.PublicKey
		if s.hybrid {
			var rep ntor.Representative
			copy(rep[:], resp[ctLen+ekLen:ctLen+ekLen+dhLen])
			X = rep.ToPublic()
		}
		// Every encoded string decodes, and ML-KEM decapsulation uses
		// implicit rejection, so garbage yields pseudorandom secrets and
		// only the mark search fails.
		cS, err := s.decodeCt(encCS)
		if err != nil {
			return nil, ErrInvalidHandshake
		}
		for _, k := range hs.keys {
			ks, err := k.kem.Decapsulate(cS)
			if err != nil {
				return nil, ErrInvalidHandshake
			}
			static := ks
			if s.hybrid {
				bX, err := x25519(k.dh.Private(), X)
				if err != nil {
					bX = make([]byte, pqDHLength) // low-order point: mark cannot match
				}
				static = append(static, bX...)
			}
			mac := hmac.New(sha256.New, pqMacKey(s, static, hs.nodeID))
			mac.Write(clientKM)
			hs.cands = append(hs.cands, pqServerCandidate{static, mac, mac.Sum(nil)[:markLength]})
		}
	}

	// The client sends nothing after MAC_C, so only the tail is examined.
	pos, which := -1, -1
	for i, c := range hs.cands {
		if p := findMarkMac(c.mark, resp, s.clientKM(), maxHandshakeLength, true); p != -1 && which == -1 {
			pos, which = p, i
		}
	}
	if pos == -1 {
		if len(resp) >= maxHandshakeLength {
			return nil, ErrInvalidHandshake
		}
		return nil, ErrMarkNotFoundYet
	}
	hs.static, hs.mac = hs.cands[which].static, hs.cands[which].mac

	macRx := resp[pos+markLength : pos+markLength+macLength]
	macFound := false
	for _, off := range []int64{0, -1, 1} {
		epochHour := []byte(strconv.FormatInt(getEpochHour()+off, 10))
		hs.mac.Reset()
		hs.mac.Write(resp[:pos+markLength])
		hs.mac.Write(epochHour)
		if hmac.Equal(hs.mac.Sum(nil)[:macLength], macRx) {
			if filter.TestAndSet(time.Now(), macRx) {
				return nil, ErrReplayedHandshake
			}
			macFound = true
			hs.epochHour = epochHour
			// As in obfs4, evaluate all three MACs to reduce timing variation.
		}
	}
	if !macFound {
		return nil, ErrInvalidHandshake
	}

	clientRawEK, err := s.decodeEK(clientEncEK)
	if err != nil {
		return nil, fmt.Errorf("pq handshake: decode client EK: %w", err)
	}
	ect, err := s.encapsulate(clientRawEK)
	if err != nil {
		return nil, fmt.Errorf("pq handshake: encapsulate to client EK: %w", err)
	}
	eph := ect.SharedSecret
	serverEph := append([]byte{}, ect.Encoded...)
	if s.hybrid {
		if hs.eph == nil {
			if hs.eph, err = ntor.NewKeypair(true); err != nil {
				return nil, err
			}
		}
		var rep ntor.Representative
		copy(rep[:], resp[ctLen+ekLen:ctLen+ekLen+dhLen])
		yX, err := x25519(hs.eph.Private(), rep.ToPublic())
		if err != nil {
			return nil, ErrNtorFailed
		}
		eph = append(append([]byte{}, eph...), yX...)
		serverEph = append(serverEph, hs.eph.Representative().Bytes()[:]...)
	}
	hs.serverEph = serverEph

	keySeed, auth := pqNtorCommon(s, hs.static, eph, hs.nodeID, clientKM, serverEph)
	hs.serverAuth = auth
	return keySeed, nil
}

// generateHandshake produces the server hello
//
//	c_e' [| Y'] | AUTH (32) | P_S | M_S (16) | MAC_S (16)
//
// sized so that the hello plus trailerLen bytes matches the cover policy.
func (hs *pqServerHandshake) generateHandshake() ([]byte, error) {
	s := hs.suite
	if hs.serverEph == nil || hs.serverAuth == nil || hs.mac == nil {
		return nil, ErrInvalidHandshake
	}
	total := hs.policy.serverLength(s, hs.trailerLen) - hs.trailerLen
	if total < s.serverMin() || total+hs.trailerLen > maxHandshakeLength {
		return nil, fmt.Errorf("pq handshake: server length %d outside bounds", total)
	}

	var buf bytes.Buffer
	buf.Write(hs.serverEph)
	buf.Write(hs.serverAuth)
	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	mark := hs.mac.Sum(nil)[:markLength]

	pad := make([]byte, total-s.serverMin())
	if err := csrand.Bytes(pad); err != nil {
		return nil, err
	}
	buf.Write(pad)
	buf.Write(mark)

	hs.mac.Reset()
	hs.mac.Write(buf.Bytes())
	hs.mac.Write(hs.epochHour)
	buf.Write(hs.mac.Sum(nil)[:macLength])
	return buf.Bytes(), nil
}
