//go:build pqobfs

package obfs4

import (
	"testing"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
)

// FuzzPQServerParse feeds arbitrary bytes (a probe, a truncated or mutated
// hello) to the bridge's parser for every suite: it must return an error or
// ErrMarkNotFoundYet, never panic, and never accept a mutated hello.
func FuzzPQServerParse(f *testing.F) {
	f.Add([]byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, cut uint16) {
		nid, kp, _ := pqTestSetup(t)
		filter, _ := replayfilter.New(time.Minute)
		for _, s := range []pqSuite{{}, {defaultEnc: true}} {
			hs := &pqServerHandshake{suite: s, nodeID: nid, keys: []pqBridgeKey{{kem: kp}}, policy: pqFixedCover()}
			buf := data
			if len(buf) > 9000 {
				buf = buf[:9000]
			}
			if _, err := hs.parseClientHandshake(filter, buf); err == nil {
				t.Fatal("accepted arbitrary input")
			}
		}
		// A real hello with one byte flipped must be rejected.
		ch, _ := newPQClientHandshake(nid, kp.RawEncapsulationKey())
		hello, _ := ch.generateHandshake()
		i := int(cut) % len(hello)
		hello[i] ^= 0x80
		hs := newPQServerHandshake(nid, kp)
		if _, err := hs.parseClientHandshake(filter, hello); err == nil {
			t.Fatalf("accepted a hello mutated at %d", i)
		}
	})
}

// FuzzPQClientParse: the client's parser never panics or accepts arbitrary
// server responses.
func FuzzPQClientParse(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		nid, kp, _ := pqTestSetup(t)
		ch, _ := newPQClientHandshake(nid, kp.RawEncapsulationKey())
		if _, err := ch.generateHandshake(); err != nil {
			t.Fatal(err)
		}
		if len(data) > 9000 {
			data = data[:9000]
		}
		if _, _, err := ch.parseServerHandshake(data); err == nil {
			t.Fatal("accepted arbitrary server response")
		}
	})
}
