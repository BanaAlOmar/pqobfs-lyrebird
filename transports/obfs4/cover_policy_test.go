package obfs4

import (
	"io"
	"net"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

func TestParseCoverPolicies(t *testing.T) {
	for _, s := range []string{"", "off", "jitter=300", "target=1500,jitter=500", "target=2000"} {
		if _, err := parseRespPolicy(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"target", "speed=3", "target=-1", "jitter=x"} {
		if _, err := parseRespPolicy(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
	if f, err := parsePadFloor("2440:1361"); err != nil || f.client != 2440 || f.server != 1361 {
		t.Fatalf("pad-floor: %v %v", f, err)
	}
	for _, s := range []string{"2440", "a:b", "9000:10", "10:-1"} {
		if _, err := parsePadFloor(s); err == nil {
			t.Errorf("pad-floor %q accepted", s)
		}
	}
}

// The floor makes obfs4 first flights uniform on [floor, 8192].
func TestPadFloorRange(t *testing.T) {
	f := padFloor{client: 2440, server: 1361}
	cmin, cmax, smin, smax := 1<<30, 0, 1<<30, 0
	for i := 0; i < 20000; i++ {
		c := clientMinHandshakeLength + f.clientPadLen()
		s := serverMinHandshakeLength + inlineSeedFrameLength + f.serverPadLen()
		cmin, cmax = min(cmin, c), max(cmax, c)
		smin, smax = min(smin, s), max(smax, s)
	}
	if cmin < 2440 || cmax > maxHandshakeLength || smin < 1361 || smax > maxHandshakeLength {
		t.Fatalf("client [%d,%d], server [%d,%d]", cmin, cmax, smin, smax)
	}
	if cmin > 2460 || cmax < 8170 || smin > 1381 || smax < 8170 {
		t.Fatalf("range not covered: client [%d,%d], server [%d,%d]", cmin, cmax, smin, smax)
	}
}

func obfs4Echo(t *testing.T, sargs pt.Args) (net.Listener, *pt.Args) {
	sf, err := new(Transport).ServerFactory(t.TempDir(), &sargs)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				c, err := sf.WrapConn(raw)
				if err != nil {
					raw.Close()
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return ln, sf.Args()
}

func obfs4Roundtrip(t *testing.T, addr string, bargs *pt.Args) time.Duration {
	cf, _ := new(Transport).ClientFactory("")
	ca, err := cf.ParseArgs(bargs)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	c, err := cf.Dial("tcp", addr, net.Dial, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	d := time.Since(t0)
	msg := []byte("coordinated cover")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != string(msg) {
		t.Fatalf("echo: %q %v", got, err)
	}
	return d
}

// A floor-enabled bridge works with unmodified clients and vice versa.
func TestPadFloorBackwardCompatible(t *testing.T) {
	floor := pt.Args{}
	floor.Add(padFloorArg, "2440:1361")
	ln, bargs := obfs4Echo(t, floor)
	defer ln.Close()
	if v, _ := bargs.Get(padFloorArg); v != "2440:1361" {
		t.Fatalf("bridge line lacks pad-floor: %v", bargs)
	}
	obfs4Roundtrip(t, ln.Addr().String(), bargs) // floor-aware client

	old := pt.Args{} // same bridge, client that ignores the floor
	for k, v := range *bargs {
		if k != padFloorArg {
			old[k] = v
		}
	}
	obfs4Roundtrip(t, ln.Addr().String(), &old)

	ln2, bargs2 := obfs4Echo(t, pt.Args{}) // unmodified bridge, floor-aware client
	defer ln2.Close()
	bargs2.Add(padFloorArg, "2440:1361")
	obfs4Roundtrip(t, ln2.Addr().String(), bargs2)
}

// With a target, the response is never released before arrival + target.
func TestRespDelayTarget(t *testing.T) {
	sargs := pt.Args{}
	sargs.Add(respDelayArg, "target=3000,jitter=0")
	ln, bargs := obfs4Echo(t, sargs)
	defer ln.Close()
	for i := 0; i < 20; i++ {
		if d := obfs4Roundtrip(t, ln.Addr().String(), bargs); d < 3*time.Millisecond {
			t.Fatalf("handshake completed in %v, before the 3 ms target", d)
		}
	}
}

// TestAnchorReadBeforeWork checks that the anchor is the hello's arrival, not
// the end of work the bridge does after accepting the connection.
func TestAnchorReadBeforeWork(t *testing.T) {
	srv, cli := net.Pipe()
	defer srv.Close()
	defer cli.Close()
	p := respPolicy{target: 2 * time.Millisecond, on: true}
	sent := make(chan time.Time, 1)
	go func() {
		t0 := time.Now()
		sent <- t0
		_, _ = cli.Write([]byte("hello"))
	}()
	first, arrive, err := p.anchorRead(srv)
	if err != nil || string(first) != "hello" {
		t.Fatalf("anchorRead = %q, %v", first, err)
	}
	time.Sleep(3 * time.Millisecond) // per-connection work after the anchor
	if d := arrive.Sub(<-sent); d < 0 || d > time.Millisecond {
		t.Fatalf("anchor %v after the write; want the arrival time", d)
	}
	if _, at, _ := (respPolicy{}).anchorRead(srv); !at.IsZero() {
		t.Fatal("anchorRead must do nothing when the policy is off")
	}
}
