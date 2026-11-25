//go:build measure && amd64

package mlkem_kemeleon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// TestMeasureAVXTransition measures HMAC-SHA256 over 4 KiB (the handshake's
// MAC input) on its own, immediately after a CIRCL ML-KEM decapsulation, and
// after a decapsulation followed by VZEROUPPER.
//
//	PQM_OUT=/tmp/pqm go test -tags measure -run TestMeasureAVXTransition -v ./internal/mlkem_kemeleon/
func TestMeasureAVXTransition(t *testing.T) {
	pk, sk, _ := mlkem768.GenerateKeyPair(nil)
	ct := make([]byte, mlkem768.CiphertextSize)
	ss := make([]byte, mlkem768.SharedKeySize)
	seed := make([]byte, mlkem768.EncapsulationSeedSize)
	pk.EncapsulateTo(ct, ss, seed)
	buf := make([]byte, 4096)
	key := make([]byte, 32)
	const N = 2000
	mac := func() time.Duration {
		t0 := time.Now()
		m := hmac.New(sha256.New, key)
		m.Write(buf)
		m.Sum(nil)
		return time.Since(t0)
	}
	median := func(d []time.Duration) float64 {
		sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
		return float64(d[len(d)/2].Nanoseconds()) / 1e3
	}
	var base, without, with []time.Duration
	for i := 0; i < N; i++ {
		vzeroupper()
		base = append(base, mac())
		sk.DecapsulateTo(ss, ct)
		without = append(without, mac())
		sk.DecapsulateTo(ss, ct)
		vzeroupper()
		with = append(with, mac())
	}
	res := map[string]float64{
		"hmac_baseline_us":             median(base),
		"hmac_after_decaps_without_us": median(without),
		"hmac_after_decaps_with_us":    median(with),
	}
	t.Logf("%v", res)
	dir := os.Getenv("PQM_OUT")
	if dir == "" {
		dir = "/tmp/pqm"
	}
	b, _ := json.MarshalIndent(res, "", " ")
	_ = os.WriteFile(filepath.Join(dir, "vzeroupper.json"), b, 0o644)
}
