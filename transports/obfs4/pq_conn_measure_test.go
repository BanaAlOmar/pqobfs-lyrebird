//go:build pqobfs && measure

// Connection-level measurements for the revised paper. These drive the full
// lyrebird connection path (factories, handshake, seed frame, data channel)
// for classical obfs4 and for pqobfs under each cover policy.
//
//	PQM_OUT=/tmp/pqm PQM_LABEL=rtt0 PQM_N=300 \
//	  go test -tags "pqobfs measure" -run TestConnLatency -v ./transports/obfs4/
//
// Network conditions (delay, loss) are applied externally with tc netem on
// the loopback interface; see artifact/run_conn_experiments.sh.

package obfs4

import (
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
)

func pqmEnvInt(k string, d int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return d
}

func pqmOut(t testing.TB, name string, v interface{}) {
	dir := os.Getenv("PQM_OUT")
	if dir == "" {
		dir = "/tmp/pqm"
	}
	_ = os.MkdirAll(dir, 0o755)
	b, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// timedConn records when the first Write completes and the first Read
// returns, to separate the bridge's processing time from the network.
type timedConn struct {
	net.Conn
	firstWrite, firstRead time.Time
}

func (c *timedConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if c.firstWrite.IsZero() {
		c.firstWrite = time.Now()
	}
	return n, err
}

func (c *timedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if c.firstRead.IsZero() && n > 0 {
		c.firstRead = time.Now()
	}
	return n, err
}

type pqmTransport struct {
	name  string
	port  int
	tr    base.Transport
	sargs pt.Args
	slow  float64 // emulated slower host: processing time x slow (respPolicy.stretch)
}

func pqmTransports() []pqmTransport {
	fixed, uni, hide := pt.Args{}, pt.Args{}, pt.Args{}
	fixed.Add(pqCoverArg, "fixed")
	uni.Add(pqCoverArg, "uniform")
	hide.Add(pqCoverArg, "uniform-hide")
	b := pqmEnvInt("PQM_PORTBASE", 20000)
	coord := func(pq bool, target string) pt.Args {
		a := pt.Args{}
		if pq {
			a.Add(pqCoverArg, "uniform")
		} else {
			a.Add(padFloorArg, "2440:1361")
		}
		a.Add(respDelayArg, "target="+target+",jitter=1000")
		return a
	}
	switch os.Getenv("PQM_SET") {
	case "robust":
		// Robustness runs (jitter via PQM_JITTER_US, CPU load applied
		// externally): undefended and coordinated bridges only.
		return []pqmTransport{
			{"obfs4", b + 100, new(Transport), pt.Args{}, 0},
			{"pq-uniform", b + 300, new(PQTransport), uni, 0},
			{"obfs4-coord", b + 800, new(Transport), coord(false, "2000"), 0},
			{"pq-coord", b + 900, new(PQTransport), coord(true, "2000"), 0},
		}
	case "slow":
		// Heterogeneous pools: normal hosts and hosts whose processing takes
		// PQM_SLOW times longer, with offsets T = 2 ms and T = 6 ms.
		f := float64(pqmEnvInt("PQM_SLOW", 4))
		return []pqmTransport{
			{"obfs4-coord", b + 800, new(Transport), coord(false, "2000"), 0},
			{"pq-coord", b + 900, new(PQTransport), coord(true, "2000"), 0},
			{"obfs4-coord-slow", b + 1200, new(Transport), coord(false, "2000"), f},
			{"pq-coord-slow", b + 1300, new(PQTransport), coord(true, "2000"), f},
			{"obfs4-t6", b + 1400, new(Transport), coord(false, "6000"), 0},
			{"pq-t6", b + 1500, new(PQTransport), coord(true, "6000"), 0},
			{"obfs4-t6-slow", b + 1600, new(Transport), coord(false, "6000"), f},
			{"pq-t6-slow", b + 1700, new(PQTransport), coord(true, "6000"), f},
		}
	}
	if os.Getenv("PQM_SET") == "defense" {
		// Coordinated cover (cover_policy.go): baselines, pq-only jitter, and
		// obfs4 and pq-obfs bridges sharing a padding floor and a
		// response-time target.
		jit := func(us string) pt.Args {
			a := pt.Args{}
			a.Add(pqCoverArg, "uniform")
			a.Add(respDelayArg, "jitter="+us)
			return a
		}
		coordPQ := pt.Args{}
		coordPQ.Add(pqCoverArg, "uniform")
		coordPQ.Add(respDelayArg, "target=2000,jitter=1000")
		coordObfs := pt.Args{}
		coordObfs.Add(padFloorArg, "2440:1361")
		coordObfs.Add(respDelayArg, "target=2000,jitter=1000")
		lightPQ, lightObfs := pt.Args{}, pt.Args{}
		lightPQ.Add(pqCoverArg, "uniform")
		lightPQ.Add(respDelayArg, "target=1500,jitter=500")
		lightObfs.Add(padFloorArg, "2440:1361")
		lightObfs.Add(respDelayArg, "target=1500,jitter=500")
		return []pqmTransport{
			{"obfs4", b + 100, new(Transport), pt.Args{}, 0},
			{"pq-uniform", b + 300, new(PQTransport), uni, 0},
			{"pq-jitter500", b + 500, new(PQTransport), jit("500"), 0},
			{"pq-jitter1000", b + 600, new(PQTransport), jit("1000"), 0},
			{"pq-jitter2000", b + 700, new(PQTransport), jit("2000"), 0},
			{"obfs4-coord", b + 800, new(Transport), coordObfs, 0},
			{"pq-coord", b + 900, new(PQTransport), coordPQ, 0},
			{"obfs4-light", b + 1000, new(Transport), lightObfs, 0},
			{"pq-light", b + 1100, new(PQTransport), lightPQ, 0},
		}
	}
	return []pqmTransport{
		{"obfs4", b + 100, new(Transport), pt.Args{}, 0},
		{"pq-fixed", b + 200, new(PQTransport), fixed, 0},
		{"pq-uniform", b + 300, new(PQTransport), uni, 0},
		{"pq-uniform-hide", b + 400, new(PQTransport), hide, 0},
	}
}

// startEcho starts an echo server for a transport and returns the listener
// and bridge-line arguments.
func startEcho(t testing.TB, m pqmTransport) (net.Listener, base.ServerFactory) {
	sf, err := m.tr.ServerFactory(t.TempDir(), &m.sargs)
	if err != nil {
		t.Fatal(err)
	}
	if m.slow > 1 {
		switch f := sf.(type) {
		case *obfs4ServerFactory:
			f.resp.stretch = m.slow
		case *pqServerFactory:
			f.resp.stretch = m.slow
		}
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", m.port))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				c, err := sf.WrapConn(raw)
				if err != nil {
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(raw)
		}
	}()
	return ln, sf
}

// delayRelay listens on 127.0.0.1:0 and forwards each connection to target,
// delivering every chunk oneWay later in each direction. Together with a
// 2*oneWay pause in the dialer (standing in for the SYN/SYN-ACK exchange) it
// emulates a path with RTT = 2*oneWay. Kernel netem is not available on the
// measurement VM; loss is not emulated.
func delayRelay(t testing.TB, target string, oneWay time.Duration) net.Listener {
	return jitterRelay(t, target, oneWay, 0, 0)
}

// jitterRelay is delayRelay with, in addition, an exponentially distributed
// extra delay of mean jitter per chunk, released in order (a chunk never
// overtakes the previous one, as in a FIFO queue). port 0 picks a free port.
func jitterRelay(t testing.TB, target string, oneWay, jitter time.Duration, port int) net.Listener {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	pipe := func(dst, src net.Conn) {
		type chunk struct {
			b  []byte
			at time.Time
		}
		var last time.Time
		q := make(chan chunk, 1024)
		go func() {
			for c := range q {
				time.Sleep(time.Until(c.at))
				if _, err := dst.Write(c.b); err != nil {
					break
				}
			}
			dst.Close()
		}()
		buf := make([]byte, 65536)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				at := time.Now().Add(oneWay)
				if jitter > 0 {
					at = at.Add(time.Duration(mrand.ExpFloat64() * float64(jitter)))
				}
				if at.Before(last) {
					at = last
				}
				last = at
				q <- chunk{append([]byte{}, buf[:n]...), at}
			}
			if err != nil {
				close(q)
				return
			}
		}
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			go pipe(s, c)
			go pipe(c, s)
		}
	}()
	return ln
}

type connSample struct {
	ParseArgsUs  float64 `json:"parse_args_us"`  // client key material, before dialing
	HandshakeUs  float64 `json:"handshake_us"`   // dial start -> handshake complete
	ServerProcUs float64 `json:"server_proc_us"` // first write done -> first response byte
	FirstByteUs  float64 `json:"first_byte_us"`  // dial start -> first echoed payload byte
}

func TestConnLatency(t *testing.T) {
	n := pqmEnvInt("PQM_N", 200)
	label := os.Getenv("PQM_LABEL")
	if label == "" {
		label = "rtt0"
	}
	oneWay := time.Duration(pqmEnvInt("PQM_DELAY_MS", 0)) * time.Millisecond
	jitter := time.Duration(pqmEnvInt("PQM_JITTER_US", 0)) * time.Microsecond
	remote := pqmRemoteBridges(t) // PQM_BRIDGES: client-only mode against a remote bridge host
	out := map[string][]connSample{}
	for _, m := range pqmTransports() {
		var ln net.Listener
		var sf base.ServerFactory
		if remote != nil {
			r, ok := remote[m.name]
			if !ok {
				continue
			}
			ln, sf = r, r
		} else {
			srv, f := startEcho(t, m)
			defer srv.Close()
			ln, sf = srv, f
			if jitter > 0 {
				// The capture point (relay port = bridge port + 50) is on the
				// client's side of the jittered path, where a censor sits.
				ln = jitterRelay(t, srv.Addr().String(), oneWay, jitter, m.port+50)
			} else if oneWay > 0 {
				ln = delayRelay(t, srv.Addr().String(), oneWay)
			}
		}
		cf, _ := m.tr.ClientFactory("")
		for i := 0; i < n; i++ {
			t0 := time.Now()
			ca, err := cf.ParseArgs(sf.Args())
			if err != nil {
				t.Fatal(err)
			}
			t1 := time.Now()
			var tc *timedConn
			dial := func(network, addr string) (net.Conn, error) {
				c, err := net.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				time.Sleep(2 * oneWay) // TCP three-way handshake over the emulated path
				tc = &timedConn{Conn: c}
				return tc, nil
			}
			addr := ln.Addr().String()
			if os.Getenv("PQM_EXT_RELAY") != "" {
				// An external pqm-jitter-relay listens on bridge port + 50.
				addr = fmt.Sprintf("127.0.0.1:%d", m.port+50)
			}
			c, err := cf.Dial("tcp", addr, dial, ca)
			if err != nil {
				t.Fatalf("%s: dial: %v", m.name, err)
			}
			t2 := time.Now()
			if _, err := c.Write([]byte{0x42}); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			if _, err := io.ReadFull(c, b[:]); err != nil {
				t.Fatal(err)
			}
			t3 := time.Now()
			c.Close()
			if tc == nil {
				t.Fatal("dial hook not called")
			}
			out[m.name] = append(out[m.name], connSample{
				ParseArgsUs:  float64(t1.Sub(t0).Nanoseconds()) / 1e3,
				HandshakeUs:  float64(t2.Sub(t1).Nanoseconds()) / 1e3,
				ServerProcUs: float64(tc.firstRead.Sub(tc.firstWrite).Nanoseconds()) / 1e3,
				FirstByteUs:  float64(t3.Sub(t1).Nanoseconds()) / 1e3,
			})
		}
		if remote == nil {
			ln.Close()
		}
		med := make([]float64, 0, n)
		for _, s := range out[m.name] {
			med = append(med, s.HandshakeUs)
		}
		sort.Float64s(med)
		t.Logf("%s %s: median handshake %.0f us", label, m.name, med[len(med)/2])
	}
	pqmOut(t, "conn_latency_"+label+".json", out)
}

// TestConnThroughput measures completed handshakes per second at the bridge
// with C concurrent clients for D seconds. Client key material is generated
// in advance (as ParseArgs does before dialing), so the clients' remaining
// cost per connection is parsing the server hello.
func TestConnThroughput(t *testing.T) {
	conc := pqmEnvInt("PQM_CONC", 8)
	dur := time.Duration(pqmEnvInt("PQM_DUR", 10)) * time.Second
	res := map[string]float64{}
	for _, m := range pqmTransports()[:2] {
		ln, sf := startEcho(t, m)
		cf, _ := m.tr.ClientFactory("")
		// Pre-generate client args.
		pool := make(chan interface{}, 20000)
		var genWG sync.WaitGroup
		stopGen := make(chan struct{})
		for g := 0; g < 1; g++ {
			genWG.Add(1)
			go func() {
				defer genWG.Done()
				for {
					select {
					case <-stopGen:
						return
					default:
					}
					ca, err := cf.ParseArgs(sf.Args())
					if err != nil {
						return
					}
					select {
					case pool <- ca:
					case <-stopGen:
						return
					}
				}
			}()
		}
		poolN := pqmEnvInt("PQM_POOL", 6000)
		for len(pool) < poolN {
			time.Sleep(50 * time.Millisecond)
		}
		close(stopGen)
		genWG.Wait()

		var done int64
		start := time.Now()
		deadline := start.Add(dur)
		var wg sync.WaitGroup
		for w := 0; w < conc; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					var ca interface{}
					select {
					case ca = <-pool:
					default:
						return
					}
					c, err := cf.Dial("tcp", ln.Addr().String(), net.Dial, ca)
					if err != nil {
						continue
					}
					c.Close()
					atomic.AddInt64(&done, 1)
				}
			}()
		}
		wg.Wait()
		elapsed := time.Since(start)
		ln.Close()
		// Rate over the time actually spent; the run ends early if the
		// pre-generated pool is exhausted.
		res[m.name] = float64(done) / elapsed.Seconds()
		res[m.name+"_elapsed_s"] = elapsed.Seconds()
		res[m.name+"_completed"] = float64(done)
		t.Logf("%s: %.1f handshakes/s (concurrency %d)", m.name, res[m.name], conc)
	}
	pqmOut(t, fmt.Sprintf("throughput_c%d%s.json", conc, os.Getenv("PQM_TAG")), res)
}

type probeResult struct {
	Transport   string  `json:"transport"`
	Probe       string  `json:"probe"`
	Bytes       int     `json:"bytes"`
	CloseSec    float64 `json:"close_after_s"`
	ExpectedSec float64 `json:"expected_close_s"` // closeDelay + serverHandshakeTimeout
	Response    int     `json:"response_bytes"`
}

// TestActiveProbing sends obfs4-style probes (random payloads of several
// lengths and a replayed valid hello) to a classical obfs4 bridge and to a
// pqobfs bridge, and records how long each keeps the connection open and how
// many bytes it answers with.
func TestActiveProbing(t *testing.T) {
	lengths := []int{0, 1000, 2440, 4112, 6000, 8192, 9000}
	var mu sync.Mutex
	var results []probeResult
	var wg sync.WaitGroup
	for _, m := range pqmTransports()[:2] {
		ln, sf := startEcho(t, m)
		defer ln.Close()
		var closeDelay int
		switch f := sf.(type) {
		case *obfs4ServerFactory:
			closeDelay = f.closeDelay
		case *pqServerFactory:
			closeDelay = f.closeDelay
		}
		expected := float64(closeDelay) + serverHandshakeTimeout.Seconds()

		// Capture one valid hello for the replay probe by completing a real
		// handshake through a recording conn.
		cf, _ := m.tr.ClientFactory("")
		ca, _ := cf.ParseArgs(sf.Args())
		var rec *recordConn
		c, err := cf.Dial("tcp", ln.Addr().String(), func(n, a string) (net.Conn, error) {
			cc, err := net.Dial(n, a)
			rec = &recordConn{Conn: cc}
			return rec, err
		}, ca)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		validHello := rec.firstWrite

		probes := map[string][]byte{"replay": validHello}
		for _, l := range lengths {
			b := make([]byte, l)
			_, _ = io.ReadFull(randReader{}, b)
			probes[fmt.Sprintf("random-%d", l)] = b
		}
		for name, payload := range probes {
			for trial := 0; trial < 2; trial++ {
				wg.Add(1)
				go func(m pqmTransport, name string, payload []byte) {
					defer wg.Done()
					conn, err := net.Dial("tcp", ln.Addr().String())
					if err != nil {
						return
					}
					start := time.Now()
					_ = conn.SetDeadline(start.Add(150 * time.Second))
					if len(payload) > 0 {
						_, _ = conn.Write(payload)
					}
					nResp, _ := io.Copy(io.Discard, conn)
					el := time.Since(start).Seconds()
					conn.Close()
					mu.Lock()
					results = append(results, probeResult{m.name, name, len(payload), el, expected, int(nResp)})
					mu.Unlock()
				}(m, name, payload)
			}
		}
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool {
		if results[i].Transport != results[j].Transport {
			return results[i].Transport < results[j].Transport
		}
		return results[i].Probe < results[j].Probe
	})
	for _, r := range results {
		t.Logf("%-9s %-12s close %.2fs (expected %.0fs) resp %d", r.Transport, r.Probe, r.CloseSec, r.ExpectedSec, r.Response)
	}
	pqmOut(t, "active_probing.json", results)
}

type recordConn struct {
	net.Conn
	firstWrite []byte
}

func (c *recordConn) Write(b []byte) (int, error) {
	if c.firstWrite == nil {
		c.firstWrite = append([]byte{}, b...)
	}
	return c.Conn.Write(b)
}

type randReader struct{}

func (randReader) Read(b []byte) (int, error) {
	return len(b), csrandBytes(b)
}

func csrandBytes(b []byte) error { return csrand.Bytes(b) }

// remoteBridge stands in for both the listener (Addr) and the server factory
// (Args) of a bridge running on another host.
type remoteBridge struct {
	addr string
	args pt.Args
}

func (r *remoteBridge) Addr() net.Addr                      { a, _ := net.ResolveTCPAddr("tcp", r.addr); return a }
func (r *remoteBridge) Accept() (net.Conn, error)           { return nil, fmt.Errorf("remote") }
func (r *remoteBridge) Close() error                        { return nil }
func (r *remoteBridge) Args() *pt.Args                      { return &r.args }
func (r *remoteBridge) Transport() base.Transport           { return nil }
func (r *remoteBridge) WrapConn(net.Conn) (net.Conn, error) { return nil, fmt.Errorf("remote") }

// pqmRemoteBridges loads PQM_BRIDGES (written by TestConnServe on the bridge
// host) and points each transport at PQM_REMOTE_HOST.
func pqmRemoteBridges(t testing.TB) map[string]*remoteBridge {
	fn := os.Getenv("PQM_BRIDGES")
	if fn == "" {
		return nil
	}
	host := os.Getenv("PQM_REMOTE_HOST")
	b, err := os.ReadFile(fn)
	if err != nil {
		t.Fatal(err)
	}
	var in map[string]struct {
		Port int                 `json:"port"`
		Args map[string][]string `json:"args"`
	}
	if err := json.Unmarshal(b, &in); err != nil {
		t.Fatal(err)
	}
	out := map[string]*remoteBridge{}
	for name, v := range in {
		out[name] = &remoteBridge{fmt.Sprintf("%s:%d", host, v.Port), pt.Args(v.Args)}
	}
	return out
}

// TestConnServe runs every configuration's echo bridge on 0.0.0.0 at
// PQM_PORTBASE+{100,200,300,400} for PQM_SERVE_SECONDS and writes their
// bridge arguments to PQM_OUT/bridges.json for remote clients.
func TestConnServe(t *testing.T) {
	secs := pqmEnvInt("PQM_SERVE_SECONDS", 0)
	if secs == 0 {
		t.Skip("set PQM_SERVE_SECONDS")
	}
	info := map[string]interface{}{}
	for _, m := range pqmTransports() {
		sf, err := m.tr.ServerFactory(t.TempDir(), &m.sargs)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", m.port))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			for {
				raw, err := ln.Accept()
				if err != nil {
					return
				}
				go func(raw net.Conn) {
					c, err := sf.WrapConn(raw)
					if err != nil {
						return
					}
					defer c.Close()
					_, _ = io.Copy(c, c)
				}(raw)
			}
		}()
		info[m.name] = map[string]interface{}{"port": m.port, "args": *sf.Args()}
	}
	pqmOut(t, "bridges.json", info)
	t.Logf("serving for %d s; copy %s/bridges.json to the client", secs, os.Getenv("PQM_OUT"))
	time.Sleep(time.Duration(secs) * time.Second)
}
