//go:build pqobfs

package obfs4

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/mlkem_kemeleon"
)

// pqTestSetup builds a node ID, the bridge's static ML-KEM-768 keypair, and a
// fresh replay filter.
func pqTestSetup(t *testing.T) (*ntor.NodeID, *mlkem_kemeleon.KeyPair, *replayfilter.ReplayFilter) {
	t.Helper()
	nodeID, err := ntor.NewNodeID(make([]byte, ntor.NodeIDLength))
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	staticKP, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair (server static): %v", err)
	}
	filter, err := replayfilter.New(20 * time.Minute)
	if err != nil {
		t.Fatalf("replayfilter.New: %v", err)
	}
	return nodeID, staticKP, filter
}

// runPQHandshake drives a full client<->server exchange and returns both
// KEY_SEEDs and the two wire messages.
func runPQHandshake(t *testing.T, nodeID *ntor.NodeID, staticKP *mlkem_kemeleon.KeyPair,
	filter *replayfilter.ReplayFilter) (clientSeed, serverSeed, clientHello, serverHello []byte) {
	t.Helper()
	clientHS, err := newPQClientHandshake(nodeID, staticKP.RawEncapsulationKey())
	if err != nil {
		t.Fatalf("newPQClientHandshake: %v", err)
	}
	serverHS := newPQServerHandshake(nodeID, staticKP)

	clientHello, err = clientHS.generateHandshake()
	if err != nil {
		t.Fatalf("client generateHandshake: %v", err)
	}
	serverSeed, err = serverHS.parseClientHandshake(filter, clientHello)
	if err != nil {
		t.Fatalf("server parseClientHandshake: %v", err)
	}
	serverHello, err = serverHS.generateHandshake()
	if err != nil {
		t.Fatalf("server generateHandshake: %v", err)
	}
	n, clientSeed, err := clientHS.parseServerHandshake(serverHello)
	if err != nil {
		t.Fatalf("client parseServerHandshake: %v", err)
	}
	if n != len(serverHello) {
		t.Fatalf("parseServerHandshake consumed %d bytes, want %d", n, len(serverHello))
	}
	return
}

// TestPQHandshakeRoundTrip asserts both sides derive the same KEY_SEED.
func TestPQHandshakeRoundTrip(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)
	clientSeed, serverSeed, _, _ := runPQHandshake(t, nodeID, staticKP, filter)
	if !bytes.Equal(clientSeed, serverSeed) {
		t.Fatalf("KEY_SEED mismatch:\n client=%x\n server=%x", clientSeed, serverSeed)
	}
	if len(clientSeed) != mlkem_kemeleon.SharedSecretLen {
		t.Fatalf("KEY_SEED length = %d, want %d", len(clientSeed), mlkem_kemeleon.SharedSecretLen)
	}
}

// TestPQHandshakeReplay asserts a replayed client hello is rejected.
func TestPQHandshakeReplay(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)
	_, _, clientHello, _ := runPQHandshake(t, nodeID, staticKP, filter)

	serverHS2 := newPQServerHandshake(nodeID, staticKP)
	if _, err := serverHS2.parseClientHandshake(filter, clientHello); err != ErrReplayedHandshake {
		t.Fatalf("replay: got %v, want ErrReplayedHandshake", err)
	}
}

// TestPQHandshakeMessageLength asserts both wire messages are exactly
// LCOVER + macLength bytes and that the pre-pad minimums are as documented.
func TestPQHandshakeMessageLength(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)
	_, _, clientHello, serverHello := runPQHandshake(t, nodeID, staticKP, filter)
	if len(clientHello) != pqHandshakeLength {
		t.Fatalf("client hello length = %d, want %d", len(clientHello), pqHandshakeLength)
	}
	if len(serverHello) != pqHandshakeLength {
		t.Fatalf("server hello length = %d, want %d", len(serverHello), pqHandshakeLength)
	}
	if pqClientMinHandshakeLength != 2440 {
		t.Fatalf("client pre-pad length = %d, want 2440", pqClientMinHandshakeLength)
	}
	if pqServerMinHandshakeLength != 1316 {
		t.Fatalf("server pre-pad length = %d, want 1316", pqServerMinHandshakeLength)
	}
}

// TestPQHandshakeInvalidClientHello feeds a random hello; the server must
// return an error (implicit-rejection K_S -> mark mismatch), not panic, and
// must not have produced a response.
func TestPQHandshakeInvalidClientHello(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)

	hello := make([]byte, pqHandshakeLength)
	if _, err := io.ReadFull(rand.Reader, hello); err != nil {
		t.Fatalf("rand: %v", err)
	}
	serverHS := newPQServerHandshake(nodeID, staticKP)
	if _, err := serverHS.parseClientHandshake(filter, hello); err == nil {
		t.Fatal("expected error for random client hello, got nil")
	}
	if _, err := serverHS.generateHandshake(); err == nil {
		t.Fatal("server generated a response to an invalid hello")
	}
}

// TestPQHandshakeBridgeLineImpersonation is the property the ephemeral-only
// prototype lacked: a party that holds the bridge line (pk_S, NodeID) but not
// sk_S cannot complete the handshake as the bridge. It cannot recover K_S from
// c_S, so it can neither verify the client's mark nor produce a server hello
// the client accepts.
func TestPQHandshakeBridgeLineImpersonation(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)

	clientHS, err := newPQClientHandshake(nodeID, staticKP.RawEncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	clientHello, err := clientHS.generateHandshake()
	if err != nil {
		t.Fatal(err)
	}

	// The impostor has the same public key bytes but a different secret key:
	// model this with a fresh keypair whose public part is irrelevant, since
	// only sk_S is used on the server side.
	impostorKP, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	impostor := newPQServerHandshake(nodeID, impostorKP)
	if _, err := impostor.parseClientHandshake(filter, clientHello); err == nil {
		t.Fatal("impostor without sk_S accepted the client hello")
	}

	// Even a forged response built with the correct layout and a guessed K_S
	// must be rejected by the client.
	forged := make([]byte, pqHandshakeLength)
	if _, err := io.ReadFull(rand.Reader, forged); err != nil {
		t.Fatal(err)
	}
	if _, _, err := clientHS.parseServerHandshake(forged); err == nil {
		t.Fatal("client accepted a forged server hello")
	}
}

// TestPQHandshakeWrongStaticKey asserts a client configured with the wrong
// bridge key (e.g. a stale bridge line) is silently rejected by the bridge.
func TestPQHandshakeWrongStaticKey(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)
	otherKP, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientHS, err := newPQClientHandshake(nodeID, otherKP.RawEncapsulationKey())
	if err != nil {
		t.Fatal(err)
	}
	clientHello, err := clientHS.generateHandshake()
	if err != nil {
		t.Fatal(err)
	}
	serverHS := newPQServerHandshake(nodeID, staticKP)
	if _, err := serverHS.parseClientHandshake(filter, clientHello); err == nil {
		t.Fatal("bridge accepted a hello encapsulated to a different static key")
	}
}

// TestPQHandshakeTranscriptTamper flips one byte of each transcript field in
// turn and asserts the handshake fails: in the client hello the mark/MAC
// catch it at the bridge; in the server hello the mark/MAC or AUTH catch it
// at the client.
func TestPQHandshakeTranscriptTamper(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)

	for _, off := range []int{pqCliCtOff + 7, pqCliEKOff + 100, pqCliMarkOff + 3, pqCoverLength + 1} {
		clientHS, _ := newPQClientHandshake(nodeID, staticKP.RawEncapsulationKey())
		hello, _ := clientHS.generateHandshake()
		hello[off] ^= 0x01
		serverHS := newPQServerHandshake(nodeID, staticKP)
		if _, err := serverHS.parseClientHandshake(filter, hello); err == nil {
			t.Fatalf("bridge accepted a client hello tampered at offset %d", off)
		}
	}

	for _, off := range []int{pqSrvCtOff + 9, pqSrvAuthOff + 2, pqSrvMarkOff, pqCoverLength + 5} {
		clientHS, _ := newPQClientHandshake(nodeID, staticKP.RawEncapsulationKey())
		hello, _ := clientHS.generateHandshake()
		serverHS := newPQServerHandshake(nodeID, staticKP)
		if _, err := serverHS.parseClientHandshake(filter, hello); err != nil {
			t.Fatal(err)
		}
		resp, _ := serverHS.generateHandshake()
		resp[off] ^= 0x01
		if _, _, err := clientHS.parseServerHandshake(resp); err == nil {
			t.Fatalf("client accepted a server hello tampered at offset %d", off)
		}
	}
}

// TestPQHandshakeKeyIndependence asserts two handshakes with the same bridge
// derive different session keys (fresh ephemeral and static encapsulations).
func TestPQHandshakeKeyIndependence(t *testing.T) {
	nodeID, staticKP, filter := pqTestSetup(t)
	s1, _, _, _ := runPQHandshake(t, nodeID, staticKP, filter)
	s2, _, _, _ := runPQHandshake(t, nodeID, staticKP, filter)
	if bytes.Equal(s1, s2) {
		t.Fatal("two handshakes derived the same KEY_SEED")
	}
}
