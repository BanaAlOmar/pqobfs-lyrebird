//go:build pqobfs && measure

package obfs4

import (
	"sort"
	"testing"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/ntor"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/replayfilter"
)

// TestMeasureJunkCost measures the bridge CPU one junk connection costs: the
// prober sends random bytes in 1,448-byte segments up to obfs4's 8,192-byte
// limit and the bridge parses after each segment, as the transport does.
// Also reported: the cost of one honest handshake on the bridge.
func TestMeasureJunkCost(t *testing.T) {
	const N = 1000
	nodeID, _ := ntor.NewNodeID(make([]byte, ntor.NodeIDLength))
	filter, _ := replayfilter.New(time.Hour)
	junk := make([][]byte, N)
	for i := range junk {
		junk[i] = make([]byte, maxHandshakeLength)
		_ = csrand.Bytes(junk[i])
	}
	median := func(d []time.Duration) float64 {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return float64(d[len(d)/2].Nanoseconds()) / 1e3
	}
	feed := func(parse func([]byte) error, b []byte) {
		for cut := 1448; ; cut += 1448 {
			if cut > len(b) {
				cut = len(b)
			}
			if err := parse(b[:cut]); err != ErrMarkNotFoundYet || cut == len(b) {
				return
			}
		}
	}
	res := map[string]float64{}

	idKP, _ := ntor.NewKeypair(false)
	var d []time.Duration
	for i := 0; i < N; i++ {
		t0 := time.Now()
		skp, _ := ntor.NewKeypair(true) // obfs4 makes this per connection
		hs := newServerHandshake(nodeID, idKP, skp)
		feed(func(b []byte) error { _, err := hs.parseClientHandshake(filter, b); return err }, junk[i])
		d = append(d, time.Since(t0))
	}
	res["obfs4_junk_us"] = median(d)

	for _, sc := range []struct {
		name string
		s    pqSuite
		keys int
	}{{"pq_rejection", pqSuite{}, 1}, {"pq_default", pqSuite{defaultEnc: true}, 1},
		{"pq_hybrid", pqSuite{hybrid: true}, 1}, {"pq_rejection_2keys", pqSuite{}, 2}} {
		var keys []pqBridgeKey
		for k := 0; k < sc.keys; k++ {
			kp, _ := sc.s.generateKeyPair()
			dh, _ := ntor.NewKeypair(false)
			keys = append(keys, pqBridgeKey{kem: kp, dh: dh})
		}
		d = d[:0]
		for i := 0; i < N; i++ {
			t0 := time.Now()
			var eph *ntor.Keypair
			if sc.s.hybrid {
				eph, _ = ntor.NewKeypair(true)
			}
			hs := &pqServerHandshake{suite: sc.s, nodeID: nodeID, keys: keys, eph: eph, policy: pqFixedCover()}
			feed(func(b []byte) error { _, err := hs.parseClientHandshake(filter, b); return err }, junk[i])
			d = append(d, time.Since(t0))
		}
		res[sc.name+"_junk_us"] = median(d)

		// One honest handshake, bridge side only.
		d = d[:0]
		for i := 0; i < N; i++ {
			km, _ := newPQClientKeyMaterial(sc.s, keys[0].kem.RawEncapsulationKey())
			var pub *ntor.PublicKey
			if sc.s.hybrid {
				pub = keys[0].dh.Public()
			}
			ch, _ := newPQClientHandshakeSuite(sc.s, nodeID, keys[0].kem.RawEncapsulationKey(), pub, pqFixedCover(), km)
			hello, _ := ch.generateHandshake()
			t0 := time.Now()
			var eph *ntor.Keypair
			if sc.s.hybrid {
				eph, _ = ntor.NewKeypair(true)
			}
			hs := &pqServerHandshake{suite: sc.s, nodeID: nodeID, keys: keys, eph: eph, policy: pqFixedCover()}
			if _, err := hs.parseClientHandshake(filter, hello); err != nil {
				t.Fatal(err)
			}
			if _, err := hs.generateHandshake(); err != nil {
				t.Fatal(err)
			}
			d = append(d, time.Since(t0))
		}
		res[sc.name+"_honest_bridge_us"] = median(d)
	}
	t.Logf("%v", res)
	pqmOut(t, "junk_cost.json", res)
}
