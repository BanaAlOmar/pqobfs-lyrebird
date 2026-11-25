/*
 * Copyright (c) 2026, the pq-obfs authors
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.
 */

package obfs4

// Coordinated cover: two bridge-side and padding-side policies that let a
// mixed population of obfs4 and pq-obfs bridges present the same first-flight
// lengths and the same response timing to a passive observer.
//
//   - resp-delay (server option, not on the bridge line): the bridge releases
//     its first response no earlier than a time drawn from a target
//     distribution, measured from the arrival of the first byte of the
//     client's hello. A target above the bridge's processing time hides how
//     much work the bridge did (KEM operations for pq-obfs, one X25519 for
//     obfs4). The first read is posted as soon as the connection is accepted,
//     before any per-connection work (anchorRead), so that work cannot delay
//     the anchor.
//       off                       no change (default)
//       jitter=J                  wait an extra U[0,J] microseconds after
//                                 processing (pq-only, no coordination)
//       target=T,jitter=J         release at first-byte arrival + T + U[0,J]
//                                 microseconds
//   - pad-floor (obfs4 only, carried on the bridge line): raise the minimum
//     total length of the client and bridge first flights, "C:S" bytes, for
//     example "2440:1361" to match pq-obfs (ML-KEM-768, rejection encoding,
//     uniform cover). Both peers already search for the mark anywhere up to
//     8,192 bytes, so the change is backward compatible.

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/common/csrand"
)

const (
	respDelayArg = "resp-delay"
	padFloorArg  = "pad-floor"
)

type respPolicy struct {
	target time.Duration // 0: no target (jitter only, after processing)
	jitter time.Duration
	on     bool
	// stretch is set only by the measurement harness to emulate a slower
	// bridge host: the bridge's processing time is multiplied by stretch
	// before the release rule applies. Zero (the default) disables it.
	stretch float64
}

func parseRespPolicy(s string) (respPolicy, error) {
	var p respPolicy
	s = strings.TrimSpace(s)
	if s == "" || s == "off" {
		return p, nil
	}
	for _, kv := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok {
			return p, fmt.Errorf("resp-delay: malformed %q", kv)
		}
		us, err := strconv.Atoi(v)
		if err != nil || us < 0 || us > 1000000 {
			return p, fmt.Errorf("resp-delay: invalid value %q", v)
		}
		switch k {
		case "target":
			p.target = time.Duration(us) * time.Microsecond
		case "jitter":
			p.jitter = time.Duration(us) * time.Microsecond
		default:
			return p, fmt.Errorf("resp-delay: unknown key %q", k)
		}
	}
	p.on = p.target > 0 || p.jitter > 0
	return p, nil
}

// release blocks until the response may be sent. arrive is the time at which
// the first bytes of the client's hello were read: reads after that are
// delayed by the bridge's own parsing work (a pq-obfs bridge decapsulates as
// soon as the key material is in), so anchoring later would leak that work.
func (p respPolicy) release(arrive time.Time) {
	if !p.on {
		return
	}
	if p.stretch > 1 && !arrive.IsZero() {
		preciseSleep(time.Duration(float64(time.Since(arrive)) * (p.stretch - 1)))
	}
	var extra time.Duration
	if p.jitter > 0 {
		extra = time.Duration(csrand.Intn(int(p.jitter) + 1))
	}
	var at time.Time
	if p.target > 0 {
		at = arrive.Add(p.target + extra)
	} else {
		at = time.Now().Add(extra)
	}
	// Block in the kernel for most of the interval, then spin for the rest.
	// Go's timer overshoots by up to a millisecond, by an amount that depends
	// on the preceding allocation and garbage-collection work, so it would
	// leak part of what the policy hides (cover_wait_*.go).
	if d := time.Until(at) - 300*time.Microsecond; d > 0 {
		preciseSleep(d)
	}
	for time.Now().Before(at) {
	}
}

// padFloor holds the total first-flight floors for obfs4, in bytes.
type padFloor struct{ client, server int }

func parsePadFloor(s string) (padFloor, error) {
	var f padFloor
	c, sv, ok := strings.Cut(s, ":")
	if !ok {
		return f, fmt.Errorf("pad-floor: expected C:S, got %q", s)
	}
	var err error
	if f.client, err = strconv.Atoi(c); err != nil || f.client < 0 || f.client > maxHandshakeLength {
		return f, fmt.Errorf("pad-floor: invalid client floor %q", c)
	}
	if f.server, err = strconv.Atoi(sv); err != nil || f.server < 0 || f.server > maxHandshakeLength {
		return f, fmt.Errorf("pad-floor: invalid server floor %q", sv)
	}
	return f, nil
}

func (f padFloor) String() string { return fmt.Sprintf("%d:%d", f.client, f.server) }

// clientPadLen draws the obfs4 client padding so that the client hello is
// uniform on [max(floor, natural minimum), 8192] bytes.
func (f padFloor) clientPadLen() int {
	lo := clientMinPadLength
	if m := f.client - clientMinHandshakeLength; m > lo {
		lo = m
	}
	return csrand.IntRange(lo, clientMaxPadLength)
}

// serverPadLen does the same for the bridge's first flight, which includes
// the inline seed frame.
func (f padFloor) serverPadLen() int {
	lo := serverMinPadLength
	if m := f.server - serverMinHandshakeLength - inlineSeedFrameLength; m > lo {
		lo = m
	}
	return csrand.IntRange(lo, serverMaxPadLength)
}

// anchorRead posts the bridge's first read immediately after the connection is
// accepted, before any per-connection work such as session-key generation, and
// returns the bytes read and the time they arrived. Both transports call it
// first, so the anchor of the response-time policy does not depend on work that
// differs between them: with obfs4, generating the Elligator session key before
// the first read delayed the anchor whenever the hello arrived during key
// generation, and the obfs4 reply left measurably later than the pq-obfs reply.
// With resp-delay off it does nothing, so the transports keep their original
// order of operations.
func (p respPolicy) anchorRead(conn net.Conn) ([]byte, time.Time, error) {
	if !p.on || p.target == 0 {
		return nil, time.Time{}, nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(serverHandshakeTimeout)); err != nil {
		return nil, time.Time{}, err
	}
	buf := make([]byte, maxHandshakeLength)
	n, err := conn.Read(buf)
	return buf[:n], time.Now(), err
}
