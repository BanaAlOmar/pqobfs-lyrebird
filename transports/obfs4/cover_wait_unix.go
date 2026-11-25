//go:build unix

package obfs4

import (
	"time"

	"golang.org/x/sys/unix"
)

// preciseSleep blocks the calling OS thread in nanosleep(2), which on Linux
// overshoots by about 0.1 ms, against about 0.7 ms for Go's timer.
func preciseSleep(d time.Duration) {
	ts := unix.NsecToTimespec(int64(d))
	for {
		if err := unix.Nanosleep(&ts, &ts); err != unix.EINTR {
			return
		}
	}
}
