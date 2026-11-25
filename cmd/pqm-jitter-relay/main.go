// Command pqm-jitter-relay emulates a network path with random queueing delay
// for the coordinated-cover robustness measurements (artifact only).
//
//	pqm-jitter-relay -jitter-us 500 20150=127.0.0.1:20100 20350=127.0.0.1:20300 ...
//
// Every chunk read from one side is delivered to the other after an extra delay
// drawn from an exponential distribution with the given mean, in order (a chunk
// never overtakes the previous one, as in a FIFO queue). It runs as a separate
// process with a precise wait (nanosleep, then spin), so the bridge's own
// allocation and garbage-collection work cannot change the delays it applies.
package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func wait(at time.Time) {
	if d := time.Until(at) - 200*time.Microsecond; d > 0 {
		ts := unix.NsecToTimespec(int64(d))
		for unix.Nanosleep(&ts, &ts) == unix.EINTR {
		}
	}
	for time.Now().Before(at) {
	}
}

func pipe(dst, src net.Conn, mean time.Duration, r *rand.Rand) {
	type chunk struct {
		b  []byte
		at time.Time
	}
	q := make(chan chunk, 4096)
	go func() {
		for c := range q {
			wait(c.at)
			if _, err := dst.Write(c.b); err != nil {
				break
			}
		}
		dst.Close()
	}()
	var last time.Time
	buf := make([]byte, 65536)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			at := time.Now().Add(time.Duration(r.ExpFloat64() * float64(mean)))
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

func main() {
	jit := flag.Int("jitter-us", 0, "mean extra delay per chunk, microseconds")
	flag.Parse()
	mean := time.Duration(*jit) * time.Microsecond
	for _, m := range flag.Args() {
		lp, target, ok := strings.Cut(m, "=")
		if !ok {
			log.Fatalf("bad mapping %q", m)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:"+lp)
		if err != nil {
			log.Fatal(err)
		}
		go func(ln net.Listener, target string) {
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
				seed := time.Now().UnixNano()
				go pipe(s, c, mean, rand.New(rand.NewSource(seed)))
				go pipe(c, s, mean, rand.New(rand.NewSource(seed+1)))
			}
		}(ln, target)
	}
	select {}
}
