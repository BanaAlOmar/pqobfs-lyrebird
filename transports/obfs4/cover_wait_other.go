//go:build !unix

package obfs4

import "time"

func preciseSleep(d time.Duration) { time.Sleep(d) }
