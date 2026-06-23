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

// pqTestSetup builds a node ID, a server static EK, and a fresh replay filter.
func pqTestSetup(t *testing.T) (*ntor.NodeID, []byte, *replayfilter.ReplayFilter) {
	t.Helper()
	nodeID, err := ntor.NewNodeID(make([]byte, ntor.NodeIDLength))
	if err != nil {
		t.Fatalf("NewNodeID: %v", err)
	}
	serverStaticKP, err := mlkem_kemeleon.GenerateKeyPair(nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair (server static): %v", err)
	}
	filter, err := replayfilter.New(20 * time.Minute)
	if err != nil {
		t.Fatalf("replayfilter.New: %v", err)
	}
	return nodeID, serverStaticKP.RawEncapsulationKey(), filter
}

// TestPQHandshakeRoundTrip drives a full client<->server exchange and asserts
// both sides derive the same KEY_SEED.
func TestPQHandshakeRoundTrip(t *testing.T) {
	nodeID, serverRawEK, filter := pqTestSetup(t)

	clientHS, err := newPQClientHandshake(nodeID, serverRawEK)
	if err != nil {
		t.Fatalf("newPQClientHandshake: %v", err)
	}
	serverHS := newPQServerHandshake(nodeID, serverRawEK)

	clientHello, err := clientHS.generateHandshake()
	if err != nil {
		t.Fatalf("client generateHandshake: %v", err)
	}

	serverSeed, err := serverHS.parseClientHandshake(filter, clientHello)
	if err != nil {
		t.Fatalf("server parseClientHandshake: %v", err)
	}

	serverHello, err := serverHS.generateHandshake()
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
	if !bytes.Equal(clientSeed, serverSeed) {
		t.Fatalf("KEY_SEED mismatch:\n client=%x\n server=%x", clientSeed, serverSeed)
	}
	if len(clientSeed) != mlkem_kemeleon.SharedSecretLen {
		t.Fatalf("KEY_SEED length = %d, want %d", len(clientSeed), mlkem_kemeleon.SharedSecretLen)
	}
}

// TestPQHandshakeReplay asserts a replayed client hello is rejected.
func TestPQHandshakeReplay(t *testing.T) {
	nodeID, serverRawEK, filter := pqTestSetup(t)

	clientHS, err := newPQClientHandshake(nodeID, serverRawEK)
	if err != nil {
		t.Fatalf("newPQClientHandshake: %v", err)
	}
	clientHello, err := clientHS.generateHandshake()
	if err != nil {
		t.Fatalf("client generateHandshake: %v", err)
	}

	serverHS := newPQServerHandshake(nodeID, serverRawEK)
	if _, err := serverHS.parseClientHandshake(filter, clientHello); err != nil {
		t.Fatalf("first parseClientHandshake: %v", err)
	}

	// Replay the identical hello through a fresh server state but the same filter.
	serverHS2 := newPQServerHandshake(nodeID, serverRawEK)
	_, err = serverHS2.parseClientHandshake(filter, clientHello)
	if err != ErrReplayedHandshake {
		t.Fatalf("replay: got %v, want ErrReplayedHandshake", err)
	}
}

// TestPQHandshakeMessageLength asserts both handshake messages are exactly
// LCOVER + macLength bytes.
func TestPQHandshakeMessageLength(t *testing.T) {
	nodeID, serverRawEK, filter := pqTestSetup(t)

	clientHS, err := newPQClientHandshake(nodeID, serverRawEK)
	if err != nil {
		t.Fatalf("newPQClientHandshake: %v", err)
	}
	clientHello, err := clientHS.generateHandshake()
	if err != nil {
		t.Fatalf("client generateHandshake: %v", err)
	}
	if len(clientHello) != pqHandshakeLength {
		t.Fatalf("client hello length = %d, want %d", len(clientHello), pqHandshakeLength)
	}

	serverHS := newPQServerHandshake(nodeID, serverRawEK)
	if _, err := serverHS.parseClientHandshake(filter, clientHello); err != nil {
		t.Fatalf("server parseClientHandshake: %v", err)
	}
	serverHello, err := serverHS.generateHandshake()
	if err != nil {
		t.Fatalf("server generateHandshake: %v", err)
	}
	if len(serverHello) != pqHandshakeLength {
		t.Fatalf("server hello length = %d, want %d", len(serverHello), pqHandshakeLength)
	}
}

// TestPQHandshakeInvalidClientEK feeds a hello with a garbage EK field; the
// server must return an error (mark mismatch / decode failure), not panic.
func TestPQHandshakeInvalidClientEK(t *testing.T) {
	nodeID, serverRawEK, filter := pqTestSetup(t)

	hello := make([]byte, pqHandshakeLength)
	if _, err := io.ReadFull(rand.Reader, hello); err != nil {
		t.Fatalf("rand: %v", err)
	}

	serverHS := newPQServerHandshake(nodeID, serverRawEK)
	if _, err := serverHS.parseClientHandshake(filter, hello); err == nil {
		t.Fatal("expected error for random client hello, got nil")
	}
}
