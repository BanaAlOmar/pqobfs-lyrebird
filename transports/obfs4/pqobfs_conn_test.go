//go:build pqobfs

package obfs4

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"os"
	"testing"
	"time"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
)

// pqEchoPair starts a pqobfs server with the given cover policy and returns
// a connected client conn plus the server's bridge-line arguments.
func pqEchoServer(t testing.TB, cover string) (net.Listener, *pt.Args, chan error) {
	t.Helper()
	tr := new(PQTransport)
	sargs := pt.Args{}
	sargs.Add(pqCoverArg, cover)
	sf, err := tr.ServerFactory(t.TempDir(), &sargs)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 16)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func(raw net.Conn) {
				c, err := sf.WrapConn(raw)
				if err != nil {
					errc <- err
					return
				}
				defer c.Close()
				_, _ = io.Copy(c, c) // echo
			}(raw)
		}
	}()
	return ln, sf.Args(), errc
}

func pqDial(t testing.TB, ln net.Listener, bridgeArgs *pt.Args) net.Conn {
	t.Helper()
	tr := new(PQTransport)
	cf, _ := tr.ClientFactory("")
	ca, err := cf.ParseArgs(bridgeArgs)
	if err != nil {
		t.Fatal(err)
	}
	c, err := cf.Dial("tcp", ln.Addr().String(), net.Dial, ca)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestPQObfsTransportEndToEnd runs the full lyrebird connection path: bridge
// state and bridge line, client ParseArgs/Dial, the pq handshake, the PRNG
// seed frame, and 1 MiB of payload echoed through the obfs4 data channel.
func TestPQObfsTransportEndToEnd(t *testing.T) {
	for _, cover := range []string{"fixed", "uniform", "uniform-hide"} {
		t.Run(cover, func(t *testing.T) {
			ln, args, errc := pqEchoServer(t, cover)
			defer ln.Close()
			for i := 0; i < 5; i++ {
				c := pqDial(t, ln, args)
				msg := make([]byte, 1<<20)
				_, _ = rand.Read(msg)
				go func() { _, _ = c.Write(msg) }()
				got := make([]byte, len(msg))
				if _, err := io.ReadFull(c, got); err != nil {
					t.Fatalf("read: %v", err)
				}
				if !bytes.Equal(got, msg) {
					t.Fatal("echoed payload differs")
				}
				c.Close()
			}
			select {
			case err := <-errc:
				t.Fatalf("server: %v", err)
			default:
			}
		})
	}
}

// TestPQObfsRejectsWrongBridgeKey: a client holding a bridge line with a
// different static key is met with silence and never completes.
func TestPQObfsRejectsWrongBridgeKey(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for the client handshake timeout")
	}
	ln, _, _ := pqEchoServer(t, "fixed")
	defer ln.Close()
	_, other, _ := pqEchoServer(t, "fixed") // different bridge identity
	tr := new(PQTransport)
	cf, _ := tr.ClientFactory("")
	ca, err := cf.ParseArgs(other)
	if err != nil {
		t.Fatal(err)
	}
	ca.(*pqClientArgs).iatMode = iatNone
	done := make(chan error, 1)
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			done <- err
			return
		}
		_ = raw.SetDeadline(timeNowPlus(2))
		_, err = newPQClientConn(raw, ca.(*pqClientArgs))
		done <- err
	}()
	if err := <-done; err == nil {
		t.Fatal("handshake with the wrong bridge key succeeded")
	}
}

func timeNowPlus(sec int) time.Time { return time.Now().Add(time.Duration(sec) * time.Second) }

func pqEchoServerArgs(t testing.TB, stateDir string, sargs pt.Args) (net.Listener, *pt.Args) {
	t.Helper()
	sf, err := new(PQTransport).ServerFactory(stateDir, &sargs)
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
	return ln, sf.Args()
}

func pqEcho(t testing.TB, ln net.Listener, args *pt.Args, n int) error {
	cf, _ := new(PQTransport).ClientFactory("")
	ca, err := cf.ParseArgs(args)
	if err != nil {
		return err
	}
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return err
	}
	_ = raw.SetDeadline(time.Now().Add(3 * time.Second))
	c, err := newPQClientConn(raw, ca.(*pqClientArgs))
	if err != nil {
		raw.Close()
		return err
	}
	defer c.Close()
	msg := make([]byte, n)
	_, _ = rand.Read(msg)
	go func() { _, _ = c.Write(msg) }()
	got := make([]byte, n)
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// TestPQObfsSuitesEndToEnd covers every suite (encoding x hybrid) under each
// cover policy through the full connection path.
func TestPQObfsSuitesEndToEnd(t *testing.T) {
	for _, enc := range []string{"rejection", "default"} {
		for _, hyb := range []string{"0", "1"} {
			for _, cover := range []string{"fixed", "uniform", "uniform-hide"} {
				name := enc + "/hybrid=" + hyb + "/" + cover
				t.Run(name, func(t *testing.T) {
					sargs := pt.Args{}
					sargs.Add(pqCoverArg, cover)
					sargs.Add(pqEncodingArg, enc)
					sargs.Add(pqHybridArg, hyb)
					ln, args := pqEchoServerArgs(t, t.TempDir(), sargs)
					defer ln.Close()
					for i := 0; i < 3; i++ {
						if err := pqEcho(t, ln, args, 1<<16); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		}
	}
}

// TestPQObfsKeyRotation: after a rotation the bridge accepts both the new
// and the old bridge line until the old key's grace period ends, and only
// the new line afterwards.
func TestPQObfsKeyRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for rejected handshakes to time out")
	}
	for _, hyb := range []string{"0", "1"} {
		dir := t.TempDir()
		sargs := pt.Args{}
		sargs.Add(pqHybridArg, hyb)
		ln, oldArgs := pqEchoServerArgs(t, dir, sargs)
		ln.Close()
		if err := PQRotateKey(dir, time.Hour); err != nil {
			t.Fatal(err)
		}
		ln, newArgs := pqEchoServerArgs(t, dir, sargs)
		if a, _ := oldArgs.Get(pqCertArg); func() bool { b, _ := newArgs.Get(pqCertArg); return a == b }() {
			t.Fatal("rotation did not change the bridge line")
		}
		if err := pqEcho(t, ln, newArgs, 1024); err != nil {
			t.Fatalf("hybrid=%s new line: %v", hyb, err)
		}
		if err := pqEcho(t, ln, oldArgs, 1024); err != nil {
			t.Fatalf("hybrid=%s old line during grace: %v", hyb, err)
		}
		ln.Close()
		// Expire the retired key.
		js, _ := pqLoadOrCreateState(dir)
		for i := range js.Retired {
			js.Retired[i].Expires = time.Now().Add(-time.Second).Unix()
		}
		_ = pqWriteState(dir, js)
		ln, _ = pqEchoServerArgs(t, dir, sargs)
		if err := pqEcho(t, ln, oldArgs, 1024); err == nil {
			t.Fatalf("hybrid=%s old line accepted after expiry", hyb)
		}
		if err := pqEcho(t, ln, newArgs, 1024); err != nil {
			t.Fatalf("hybrid=%s new line after expiry: %v", hyb, err)
		}
		ln.Close()
	}
}

// TestPQObfsHybridNeedsBothKeys: in the hybrid suite, a client holding the
// right ML-KEM key but the wrong X25519 key is rejected.
func TestPQObfsHybridNeedsBothKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("waits for rejected handshakes to time out")
	}
	sargs := pt.Args{}
	sargs.Add(pqHybridArg, "1")
	ln, args := pqEchoServerArgs(t, t.TempDir(), sargs)
	defer ln.Close()
	cert, _ := args.Get(pqCertArg)
	_, other := pqEchoServerArgs(t, t.TempDir(), sargs)
	ocert, _ := other.Get(pqCertArg)
	// Splice: this bridge's NodeID and ML-KEM key, the other bridge's X25519 key.
	dec := func(s string) []byte {
		for len(s)%4 != 0 {
			s += "="
		}
		b, _ := base64.StdEncoding.DecodeString(s)
		return b
	}
	mixed := append(dec(cert)[:pqCertLength], dec(ocert)[pqCertLength:]...)
	bad := pt.Args{}
	for k, v := range *args {
		bad[k] = v
	}
	bad[pqCertArg] = []string{base64.StdEncoding.EncodeToString(mixed)}
	if err := pqEcho(t, ln, &bad, 1024); err == nil {
		t.Fatal("handshake succeeded with the wrong X25519 key")
	}
}

// TestPQObfsKeyIDBridgeLine: a bridge line with pq-id (within Tor's 510-byte
// SOCKS limit) plus the bridge-key file works; a mismatching key is refused.
func TestPQObfsKeyIDBridgeLine(t *testing.T) {
	dir := t.TempDir()
	ln, args := pqEchoServerArgs(t, dir, pt.Args{})
	defer ln.Close()
	short := pt.Args{}
	for k, v := range *args {
		if k != pqCertArg {
			short[k] = v
		}
	}
	n := 0
	for k, v := range short {
		n += len(k) + 1 + len(v[0]) + 1
	}
	if n > 510 {
		t.Fatalf("short bridge-line arguments are %d bytes", n)
	}
	cdir := t.TempDir()
	keys, _ := os.ReadFile(dir + "/" + pqKeysFile)
	_ = os.WriteFile(cdir+"/"+pqKeysFile, keys, 0600)
	cf, _ := new(PQTransport).ClientFactory(cdir)
	if _, err := cf.ParseArgs(&short); err != nil {
		t.Fatal(err)
	}
	// End to end through a client that only has pq-id.
	ca, _ := cf.ParseArgs(&short)
	c, err := cf.Dial("tcp", ln.Addr().String(), net.Dial, ca)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// A key file entry whose cert does not hash to the id is refused.
	_, other := pqEchoServerArgs(t, t.TempDir(), pt.Args{})
	ocert, _ := other.Get(pqCertArg)
	id, _ := short.Get(pqIDArg)
	_ = os.WriteFile(cdir+"/"+pqKeysFile, []byte(id+" "+ocert+"\n"), 0600)
	if _, err := cf.ParseArgs(&short); err == nil {
		t.Fatal("accepted a cert that does not match pq-id")
	}
}
