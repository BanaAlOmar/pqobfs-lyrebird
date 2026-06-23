package mlkem_kemeleon

import (
	"crypto/rand"
	"fmt"
	"io"
)

// LCOVER is the fixed cover size (in bytes) that pq-obfs handshake messages are
// padded to, normalizing the TCP segment profile across ML-KEM parameter sets
// (paper Section V-B).
const LCOVER = 4096

// NormalizePadding appends uniform random padding to msg so the result is
// exactly LCOVER bytes. It returns an error if msg is already larger than
// LCOVER.
func NormalizePadding(msg []byte) ([]byte, error) {
	if len(msg) > LCOVER {
		return nil, fmt.Errorf("mlkem_kemeleon: message of %d bytes exceeds cover size %d", len(msg), LCOVER)
	}
	out := make([]byte, LCOVER)
	copy(out, msg)
	if _, err := io.ReadFull(rand.Reader, out[len(msg):]); err != nil {
		return nil, fmt.Errorf("mlkem_kemeleon: padding: %w", err)
	}
	return out, nil
}

// ClientHelloKeyMaterial bundles the key material a pq-obfs client needs to send
// and the secrets it must retain to finish the handshake.
type ClientHelloKeyMaterial struct {
	// Keypair is the client's ephemeral ML-KEM-768 keypair. Its Representative()
	// (1156 bytes) is sent on the wire in place of the Elligator 2 representative.
	Keypair *KeyPair
	// StaticCiphertext is the encapsulation to the bridge's long-term EK, used to
	// authenticate the client to the bridge.
	StaticCiphertext []byte
	// StaticSharedSecret is the shared secret from the static encapsulation; it
	// keys the handshake MAC.
	StaticSharedSecret []byte
}

// NewClientHelloKeyMaterial generates a fresh ephemeral keypair and encapsulates
// to the bridge's raw long-term encapsulation key (bridgeRawEK). The returned
// material's Keypair.Representative() and StaticCiphertext are the wire fields;
// StaticSharedSecret is retained by the caller for MAC keying.
//
// This is a building block: the full obfs4 frame layout, MAC computation, and
// padding are assembled by the transport (see the TODO marker in
// transports/obfs4/handshake_ntor.go). It is kept here so the cryptographic core
// is testable in isolation.
func NewClientHelloKeyMaterial(bridgeRawEK []byte) (*ClientHelloKeyMaterial, error) {
	kp, err := GenerateKeyPair(nil)
	if err != nil {
		return nil, err
	}
	ct, ss, err := Encapsulate(bridgeRawEK)
	if err != nil {
		return nil, err
	}
	return &ClientHelloKeyMaterial{
		Keypair:            kp,
		StaticCiphertext:   ct,
		StaticSharedSecret: ss,
	}, nil
}
