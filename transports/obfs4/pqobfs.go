//go:build pqobfs

/*
 * pqobfs: the pq-obfs handshake (handshake_ntor_pq.go) wired into lyrebird's
 * connection path as a separate transport. Everything after the handshake --
 * framing, NaCl secretbox, the length/IAT obfuscation distributions, the PRNG
 * seed frame, and the delayed close on failure -- is the unchanged obfs4 code.
 *
 * Bridge line arguments:
 *
 *   pq-cert      base64(NodeID (20 B) || pk_S (1184 B raw ML-KEM-768 key)
 *                [|| B (32 B X25519 key) when pq-hybrid=1])
 *   pq-id        base64(SHA-256(cert)[:16]), used instead of pq-cert in the
 *                bridge line given to Tor: Tor passes transport arguments
 *                over SOCKS5, which limits them to 510 bytes, and pq-cert
 *                alone is about 1.6 kB. The client looks the full cert up
 *                in pqobfs_bridgekeys.txt in its state directory (or the
 *                file named by PQOBFS_BRIDGEKEYS) and checks it against the
 *                identifier.
 *   iat-mode     as in obfs4
 *   pq-cover     "fixed" (default), "uniform", or "uniform-hide"
 *   pq-encoding  "rejection" (default) or "default" (non-rejecting Kemeleon)
 *   pq-hybrid    "0" (default) or "1" (X25519 + ML-KEM)
 *
 * The bridge keeps NodeID, its key ring (ML-KEM seed and X25519 key of the
 * current key, plus retired keys still accepted until their expiry), the
 * DRBG seed, the IAT mode, the cover policy and the suite in
 * pqobfs_state.json. PQRotateKey (cmd/pqobfs-rotate) adds a new current key
 * and keeps the previous one for a grace period.
 */

package obfs4

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/drbg"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/probdist"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4/framing"
)

const (
	pqTransportName = "pqobfs"
	pqCertArg       = "pq-cert"
	pqCoverArg      = "pq-cover"
	pqEncodingArg   = "pq-encoding"
	pqHybridArg     = "pq-hybrid"
	pqIDArg         = "pq-id"
	pqKeysFile      = "pqobfs_bridgekeys.txt"
	pqStateFile     = "pqobfs_state.json"
	pqCertLength    = ntor.NodeIDLength + mlkem_kemeleon.RawEKLen
)

// parsePQSuite maps the pq-encoding and pq-hybrid arguments to a suite.
func parsePQSuite(enc, hybrid string) (pqSuite, error) {
	var s pqSuite
	switch enc {
	case "", "rejection":
	case "default":
		s.defaultEnc = true
	default:
		return s, fmt.Errorf("invalid %s '%s'", pqEncodingArg, enc)
	}
	switch hybrid {
	case "", "0":
	case "1":
		s.hybrid = true
	default:
		return s, fmt.Errorf("invalid %s '%s'", pqHybridArg, hybrid)
	}
	return s, nil
}

func pqSuiteArgs(s pqSuite) (enc, hybrid string) {
	enc, hybrid = "rejection", "0"
	if s.defaultEnc {
		enc = "default"
	}
	if s.hybrid {
		hybrid = "1"
	}
	return
}

// parsePQCover maps a pq-cover argument to a policy.
func parsePQCover(s string) (pqCoverPolicy, error) {
	switch s {
	case "", "fixed":
		return pqFixedCover(), nil
	case "uniform":
		return pqUniformCover(false), nil
	case "uniform-hide":
		return pqUniformCover(true), nil
	}
	return pqCoverPolicy{}, fmt.Errorf("invalid %s '%s'", pqCoverArg, s)
}

// PQTransport is the pq-obfs transport.
type PQTransport struct{}

// Name returns the transport name.
func (t *PQTransport) Name() string { return pqTransportName }

// ClientFactory returns a pq-obfs client factory.
func (t *PQTransport) ClientFactory(stateDir string) (base.ClientFactory, error) {
	return &pqClientFactory{transport: t, stateDir: stateDir}, nil
}

// pqCertID is the short identifier of a bridge cert: base64 of the first 16
// bytes of SHA-256(cert), without padding.
func pqCertID(cert []byte) string {
	h := sha256.Sum256(cert)
	return base64.RawStdEncoding.EncodeToString(h[:16])
}

// pqLookupCert finds the cert for id in the client's bridge-key file. Each
// line is "<pq-id> <pq-cert>"; blank lines and # comments are ignored.
func pqLookupCert(stateDir, id string) (string, error) {
	fn := os.Getenv("PQOBFS_BRIDGEKEYS")
	if fn == "" {
		fn = path.Join(stateDir, pqKeysFile)
	}
	b, err := os.ReadFile(fn)
	if err != nil {
		return "", fmt.Errorf("%s=%s given but no bridge-key file: %w", pqIDArg, id, err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && !strings.HasPrefix(f[0], "#") && f[0] == id {
			return f[1], nil
		}
	}
	return "", fmt.Errorf("no key for %s=%s in %s", pqIDArg, id, fn)
}

// ---------------------------------------------------------------- server ---

type pqJSONKey struct {
	MLKEMSeed string `json:"mlkem-seed"`
	X25519Key string `json:"x25519-key"`
	Expires   int64  `json:"expires,omitempty"` // unix seconds; 0 = current key
}

type pqJSONState struct {
	NodeID    string      `json:"node-id"`
	MLKEMSeed string      `json:"mlkem-seed"` // current key
	X25519Key string      `json:"x25519-key"` // current key (hybrid)
	Retired   []pqJSONKey `json:"retired,omitempty"`
	DrbgSeed  string      `json:"drbg-seed"`
	IATMode   int         `json:"iat-mode"`
	Cover     string      `json:"cover"`
	Encoding  string      `json:"encoding,omitempty"`
	Hybrid    string      `json:"hybrid,omitempty"`
}

func pqNewKeyMaterial() (seed, x string, err error) {
	b := make([]byte, mlkem_kemeleon.StaticSeedSize)
	if err = csrand.Bytes(b); err != nil {
		return
	}
	kp, err := ntor.NewKeypair(false)
	if err != nil {
		return
	}
	return hex.EncodeToString(b), kp.Private().Hex(), nil
}

func pqBridgeKeyFrom(seedHex, xHex string) (pqBridgeKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return pqBridgeKey{}, err
	}
	kem, err := mlkem_kemeleon.KeyPairFromSeed(seed)
	if err != nil {
		return pqBridgeKey{}, err
	}
	k := pqBridgeKey{kem: kem}
	if xHex != "" {
		if k.dh, err = ntor.KeypairFromHex(xHex); err != nil {
			return pqBridgeKey{}, err
		}
	}
	return k, nil
}

func pqWriteState(stateDir string, js *pqJSONState) error {
	b, err := json.Marshal(js)
	if err != nil {
		return err
	}
	return os.WriteFile(path.Join(stateDir, pqStateFile), b, 0600)
}

// PQRotateKey makes a fresh key the bridge's current key and keeps the
// previous current key, accepted until grace from now, so clients holding
// the old bridge line keep working while the new line is distributed.
// Expired retired keys are dropped. The bridge must be restarted to pick up
// the change; its new bridge line is printed in the server's Args.
func PQRotateKey(stateDir string, grace time.Duration) error {
	js, err := pqLoadOrCreateState(stateDir)
	if err != nil {
		return err
	}
	now := time.Now()
	var keep []pqJSONKey
	for _, k := range js.Retired {
		if k.Expires > now.Unix() {
			keep = append(keep, k)
		}
	}
	keep = append(keep, pqJSONKey{js.MLKEMSeed, js.X25519Key, now.Add(grace).Unix()})
	js.Retired = keep
	if js.MLKEMSeed, js.X25519Key, err = pqNewKeyMaterial(); err != nil {
		return err
	}
	return pqWriteState(stateDir, js)
}

func pqLoadOrCreateState(stateDir string) (*pqJSONState, error) {
	fn := path.Join(stateDir, pqStateFile)
	js := new(pqJSONState)
	if b, err := os.ReadFile(fn); err == nil {
		if err := json.Unmarshal(b, js); err != nil {
			return nil, fmt.Errorf("failed to load pqobfs state from '%s': %w", fn, err)
		}
		return js, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	nodeID := make([]byte, ntor.NodeIDLength)
	if err := csrand.Bytes(nodeID); err != nil {
		return nil, err
	}
	dseed, err := drbg.NewSeed()
	if err != nil {
		return nil, err
	}
	js.NodeID = hex.EncodeToString(nodeID)
	if js.MLKEMSeed, js.X25519Key, err = pqNewKeyMaterial(); err != nil {
		return nil, err
	}
	js.DrbgSeed = dseed.Hex()
	js.Cover = "fixed"
	if err := pqWriteState(stateDir, js); err != nil {
		return nil, err
	}
	return js, nil
}

type pqServerFactory struct {
	transport base.Transport
	args      *pt.Args

	nodeID       *ntor.NodeID
	keys         []pqBridgeKey // current first, then unexpired retired keys
	suite        pqSuite
	policy       pqCoverPolicy
	lenSeed      *drbg.Seed
	iatSeed      *drbg.Seed
	iatMode      int
	replayFilter *replayfilter.ReplayFilter
	closeDelay   int
	resp         respPolicy // response-time policy (cover_policy.go), bridge-local
}

// ServerFactory returns a pq-obfs server factory. Arguments iat-mode and
// pq-cover, if present, override the state file.
func (t *PQTransport) ServerFactory(stateDir string, args *pt.Args) (base.ServerFactory, error) {
	js, err := pqLoadOrCreateState(stateDir)
	if err != nil {
		return nil, err
	}
	if v, ok := args.Get(iatArg); ok {
		if js.IATMode, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("malformed iat-mode '%s'", v)
		}
	}
	if v, ok := args.Get(pqCoverArg); ok {
		js.Cover = v
	}
	if v, ok := args.Get(pqEncodingArg); ok {
		js.Encoding = v
	}
	if v, ok := args.Get(pqHybridArg); ok {
		js.Hybrid = v
	}
	var resp respPolicy
	if v, ok := args.Get(respDelayArg); ok {
		if resp, err = parseRespPolicy(v); err != nil {
			return nil, err
		}
	}
	suite, err := parsePQSuite(js.Encoding, js.Hybrid)
	if err != nil {
		return nil, err
	}
	if js.IATMode < iatNone || js.IATMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%d'", js.IATMode)
	}
	policy, err := parsePQCover(js.Cover)
	if err != nil {
		return nil, err
	}
	nodeID, err := ntor.NodeIDFromHex(js.NodeID)
	if err != nil {
		return nil, err
	}
	cur, err := pqBridgeKeyFrom(js.MLKEMSeed, js.X25519Key)
	if err != nil {
		return nil, err
	}
	if suite.hybrid && cur.dh == nil {
		return nil, fmt.Errorf("pqobfs state has no X25519 key for the hybrid suite")
	}
	keys := []pqBridgeKey{cur}
	for _, r := range js.Retired {
		if r.Expires <= time.Now().Unix() {
			continue
		}
		k, err := pqBridgeKeyFrom(r.MLKEMSeed, r.X25519Key)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	lenSeed, err := drbg.SeedFromHex(js.DrbgSeed)
	if err != nil {
		return nil, err
	}
	var iatSeed *drbg.Seed
	if js.IATMode != iatNone {
		src := sha256.Sum256(lenSeed.Bytes()[:])
		if iatSeed, err = drbg.SeedFromBytes(src[:]); err != nil {
			return nil, err
		}
	}

	cert := append(append([]byte{}, nodeID.Bytes()[:]...), cur.kem.RawEncapsulationKey()...)
	if suite.hybrid {
		cert = append(cert, cur.dh.Public().Bytes()[:]...)
	}
	ptArgs := pt.Args{}
	ptArgs.Add(pqCertArg, strings.TrimRight(base64.StdEncoding.EncodeToString(cert), "="))
	ptArgs.Add(iatArg, strconv.Itoa(js.IATMode))
	ptArgs.Add(pqCoverArg, js.Cover)
	encArg, hybArg := pqSuiteArgs(suite)
	ptArgs.Add(pqEncodingArg, encArg)
	ptArgs.Add(pqHybridArg, hybArg)

	// As obfs4 does, write a ready-to-use bridge line (placeholders for the
	// address and fingerprint) next to the state file. Tor limits transport
	// arguments to 510 bytes, so the line carries pq-id; the full cert goes
	// into pqobfs_bridgekeys.txt, which clients place in their state
	// directory.
	certB64 := strings.TrimRight(base64.StdEncoding.EncodeToString(cert), "=")
	id := pqCertID(cert)
	ptArgs.Add(pqIDArg, id)
	line := fmt.Sprintf("Bridge %s <IP ADDRESS>:<PORT> <FINGERPRINT> %s=%s %s=%d %s=%s %s=%s %s=%s\n",
		pqTransportName, pqIDArg, id, iatArg, js.IATMode, pqCoverArg, js.Cover,
		pqEncodingArg, encArg, pqHybridArg, hybArg)
	if err := os.WriteFile(path.Join(stateDir, "pqobfs_bridgeline.txt"),
		[]byte("# pqobfs torrc client bridge line (generated; edits have no effect)\n\n"+line), 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path.Join(stateDir, pqKeysFile), []byte(id+" "+certB64+"\n"), 0600); err != nil {
		return nil, err
	}

	filter, err := replayfilter.New(replayTTL)
	if err != nil {
		return nil, err
	}
	hd, err := drbg.NewHashDrbg(lenSeed)
	if err != nil {
		return nil, err
	}
	closeDelay := rand.New(hd).Intn(maxCloseDelay)

	return &pqServerFactory{t, &ptArgs, nodeID, keys, suite, policy, lenSeed, iatSeed,
		js.IATMode, filter, closeDelay, resp}, nil
}

func (sf *pqServerFactory) Transport() base.Transport { return sf.transport }
func (sf *pqServerFactory) Args() *pt.Args            { return sf.args }

func (sf *pqServerFactory) WrapConn(conn net.Conn) (net.Conn, error) {
	// Same order as obfs4: with a response-time target, read first and
	// anchor the policy at the hello's arrival (cover_policy.go).
	acceptTime := time.Now()
	first, arrive, anchorErr := sf.resp.anchorRead(conn)
	lenDist := probdist.New(sf.lenSeed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if sf.iatSeed != nil {
		iatDist = probdist.New(sf.iatSeed, 0, maxIATDelay, biasedDist)
	}
	c := &obfs4Conn{conn, true, lenDist, iatDist, sf.iatMode, bytes.NewBuffer(nil),
		bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	// As obfs4 does with its session key, make the bridge's ephemeral
	// X25519 key (hybrid suites) before reading, so Elligator's retries do
	// not fall between the client's hello and the response.
	var eph *ntor.Keypair
	if sf.suite.hybrid {
		var err error
		if eph, err = ntor.NewKeypair(true); err != nil {
			return nil, err
		}
	}

	startTime := time.Now()
	if !arrive.IsZero() || anchorErr != nil {
		startTime = acceptTime
	}
	if anchorErr != nil {
		c.closeAfterDelay(&obfs4ServerFactory{closeDelay: sf.closeDelay}, startTime)
		return nil, anchorErr
	}
	if err := c.pqServerHandshake(sf, eph, first, arrive); err != nil {
		// Same delayed close as obfs4, so a failed probe is answered
		// identically by both transports.
		c.closeAfterDelay(&obfs4ServerFactory{closeDelay: sf.closeDelay}, startTime)
		return nil, err
	}
	return c, nil
}

func (conn *obfs4Conn) pqServerHandshake(sf *pqServerFactory, eph *ntor.Keypair, first []byte, arrive time.Time) error {
	hs := &pqServerHandshake{suite: sf.suite, nodeID: sf.nodeID, keys: sf.keys, eph: eph, policy: sf.policy}
	hs.trailerLen = inlineSeedFrameLength
	if err := conn.Conn.SetDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return err
	}

	var hsBuf [maxHandshakeLength]byte
	pending := first
	for {
		var chunk []byte
		if len(pending) > 0 {
			// Bytes already read by anchorRead.
			chunk, pending = pending, nil
		} else {
			n, err := conn.Conn.Read(hsBuf[:])
			if err != nil {
				return err
			}
			if arrive.IsZero() {
				// Anchor the response-time policy at the first bytes of the hello:
				// later reads are delayed by the bridge's own parsing work.
				arrive = time.Now()
			}
			chunk = hsBuf[:n]
		}
		conn.receiveBuffer.Write(chunk)
		seed, err := hs.parseClientHandshake(sf.replayFilter, conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		conn.receiveBuffer.Reset()
		if err := conn.Conn.SetDeadline(time.Time{}); err != nil {
			return nil
		}
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[framing.KeyLength:])
		conn.decoder = framing.NewDecoder(okm[:framing.KeyLength])
		break
	}

	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	var frameBuf bytes.Buffer
	frameBuf.Write(blob)
	if err := conn.makePacket(&frameBuf, packetTypePrngSeed, sf.lenSeed.Bytes()[:], 0); err != nil {
		return err
	}
	sf.resp.release(arrive)
	_, err = conn.Conn.Write(frameBuf.Bytes())
	return err
}

// ---------------------------------------------------------------- client ---

type pqClientFactory struct {
	transport base.Transport
	stateDir  string
}

type pqClientArgs struct {
	nodeID   *ntor.NodeID
	rawEK    []byte
	serverDH *ntor.PublicKey
	suite    pqSuite
	policy   pqCoverPolicy
	iatMode  int
	km       *pqClientKeyMaterial
}

func (cf *pqClientFactory) Transport() base.Transport { return cf.transport }

// ParseArgs parses the bridge line and, as obfs4 does for its session key,
// generates all per-connection key material before the TCP connection is
// opened: the ephemeral ML-KEM keypair and the encapsulation to pk_S, each
// with its Kemeleon rejection-sampling loop. The retries therefore never
// appear between the TCP handshake and the first payload.
func (cf *pqClientFactory) ParseArgs(args *pt.Args) (interface{}, error) {
	certStr, ok := args.Get(pqCertArg)
	id, haveID := args.Get(pqIDArg)
	if !ok {
		if !haveID {
			return nil, fmt.Errorf("missing argument '%s' or '%s'", pqCertArg, pqIDArg)
		}
		var err error
		if certStr, err = pqLookupCert(cf.stateDir, id); err != nil {
			return nil, err
		}
	}
	if pad := len(certStr) % 4; pad != 0 {
		certStr += strings.Repeat("=", 4-pad)
	}
	cert, err := base64.StdEncoding.DecodeString(certStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s: %w", pqCertArg, err)
	}
	if haveID && pqCertID(cert) != id {
		return nil, fmt.Errorf("%s does not match %s", pqCertArg, pqIDArg)
	}
	encStr, _ := args.Get(pqEncodingArg)
	hybStr, _ := args.Get(pqHybridArg)
	suite, err := parsePQSuite(encStr, hybStr)
	if err != nil {
		return nil, err
	}
	want := pqCertLength + suite.dhLen()
	if len(cert) != want {
		return nil, fmt.Errorf("%s has length %d, want %d", pqCertArg, len(cert), want)
	}
	nodeID, err := ntor.NewNodeID(cert[:ntor.NodeIDLength])
	if err != nil {
		return nil, err
	}
	rawEK := cert[ntor.NodeIDLength:pqCertLength]
	var serverDH *ntor.PublicKey
	if suite.hybrid {
		if serverDH, err = ntor.NewPublicKey(cert[pqCertLength:]); err != nil {
			return nil, err
		}
	}

	iatStr, ok := args.Get(iatArg)
	if !ok {
		return nil, fmt.Errorf("missing argument '%s'", iatArg)
	}
	iatMode, err := strconv.Atoi(iatStr)
	if err != nil || iatMode < iatNone || iatMode > iatParanoid {
		return nil, fmt.Errorf("invalid iat-mode '%s'", iatStr)
	}
	coverStr, _ := args.Get(pqCoverArg)
	policy, err := parsePQCover(coverStr)
	if err != nil {
		return nil, err
	}

	km, err := newPQClientKeyMaterial(suite, rawEK)
	if err != nil {
		return nil, err
	}
	return &pqClientArgs{nodeID, rawEK, serverDH, suite, policy, iatMode, km}, nil
}

func (cf *pqClientFactory) Dial(network, addr string, dialFn base.DialFunc, args interface{}) (net.Conn, error) {
	ca, ok := args.(*pqClientArgs)
	if !ok {
		return nil, fmt.Errorf("invalid argument type for args")
	}
	conn, err := dialFn(network, addr)
	if err != nil {
		return nil, err
	}
	c, err := newPQClientConn(conn, ca)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return c, nil
}

func (cf *pqClientFactory) OnEvent(f func(base.TransportEvent)) {}

func newPQClientConn(conn net.Conn, args *pqClientArgs) (*obfs4Conn, error) {
	seed, err := drbg.NewSeed()
	if err != nil {
		return nil, err
	}
	lenDist := probdist.New(seed, 0, framing.MaximumSegmentLength, biasedDist)
	var iatDist *probdist.WeightedDist
	if args.iatMode != iatNone {
		src := sha256.Sum256(seed.Bytes()[:])
		iatSeed, err := drbg.SeedFromBytes(src[:])
		if err != nil {
			return nil, err
		}
		iatDist = probdist.New(iatSeed, 0, maxIATDelay, biasedDist)
	}
	c := &obfs4Conn{conn, false, lenDist, iatDist, args.iatMode, bytes.NewBuffer(nil),
		bytes.NewBuffer(nil), make([]byte, consumeReadSize), nil, nil}

	if err := conn.SetDeadline(time.Now().Add(clientHandshakeTimeout)); err != nil {
		return nil, err
	}
	if err := c.pqClientHandshake(args); err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return c, nil
}

func (conn *obfs4Conn) pqClientHandshake(args *pqClientArgs) error {
	km := args.km
	args.km = nil // key material is single-use
	hs, err := newPQClientHandshakeSuite(args.suite, args.nodeID, args.rawEK, args.serverDH, args.policy, km)
	if err != nil {
		return err
	}
	blob, err := hs.generateHandshake()
	if err != nil {
		return err
	}
	if _, err = conn.Conn.Write(blob); err != nil {
		return err
	}

	var hsBuf [maxHandshakeLength]byte
	for {
		n, err := conn.Conn.Read(hsBuf[:])
		if err != nil {
			return err
		}
		conn.receiveBuffer.Write(hsBuf[:n])
		n, seed, err := hs.parseServerHandshake(conn.receiveBuffer.Bytes())
		if err == ErrMarkNotFoundYet {
			continue
		} else if err != nil {
			return err
		}
		_ = conn.receiveBuffer.Next(n)
		okm := ntor.Kdf(seed, framing.KeyLength*2)
		conn.encoder = framing.NewEncoder(okm[:framing.KeyLength])
		conn.decoder = framing.NewDecoder(okm[framing.KeyLength:])
		return nil
	}
}
