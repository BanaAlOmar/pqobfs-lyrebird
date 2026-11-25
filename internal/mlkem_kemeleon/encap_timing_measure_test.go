//go:build measure

package mlkem_kemeleon

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

// TestMeasureEncapTiming records the bridge's encapsulate-and-encode time for
// both encodings. The rejection encoding retries with probability ~0.22 per
// attempt, which shows up as a multimodal distribution; the default encoding
// never retries. Output: $PQM_OUT/encap_timing.json.
func TestMeasureEncapTiming(t *testing.T) {
	kp, err := GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	ek := kp.RawEncapsulationKey()
	const n = 20000
	run := func(f func() error) map[string]float64 {
		d := make([]float64, n)
		for i := 0; i < 500; i++ {
			_ = f()
		}
		for i := range d {
			s := time.Now()
			if err := f(); err != nil {
				t.Fatal(err)
			}
			d[i] = float64(time.Since(s).Nanoseconds()) / 1e3
		}
		sort.Float64s(d)
		var m, v float64
		for _, x := range d {
			m += x
		}
		m /= n
		for _, x := range d {
			v += (x - m) * (x - m)
		}
		q := func(p float64) float64 { return d[int(p*float64(n-1))] }
		return map[string]float64{"mean_us": m, "sd_us": sqrt(v / (n - 1)), "p10_us": q(.1), "p50_us": q(.5), "p75_us": q(.75), "p90_us": q(.9), "p99_us": q(.99), "n": n}
	}
	out := map[string]map[string]float64{
		"rejection": run(func() error { _, err := EncapsulateEncoded(ek); return err }),
		"default":   run(func() error { _, err := EncapsulateEncodedDefault(ek); return err }),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	dir := os.Getenv("PQM_OUT")
	if dir == "" {
		dir = "."
	}
	_ = os.WriteFile(dir+"/encap_timing.json", b, 0o644)
	t.Logf("%s", b)
}

func sqrt(x float64) float64 {
	z := x
	for i := 0; i < 60 && z > 0; i++ {
		z = (z + x/z) / 2
	}
	return z
}
