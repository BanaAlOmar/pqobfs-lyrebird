//go:build pqobfs

// Command pqobfs-rotate rotates a pqobfs bridge's long-term key.
//
//	pqobfs-rotate -state /var/lib/tor/pt_state -grace 720h
//
// The new key becomes current; the previous key stays accepted for the grace
// period so that clients holding the old bridge line keep working while the
// new line is distributed. Restart the bridge afterwards.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"
)

func main() {
	state := flag.String("state", "", "pluggable-transport state directory of the bridge")
	grace := flag.Duration("grace", 30*24*time.Hour, "how long the previous key stays valid")
	flag.Parse()
	if *state == "" {
		fmt.Fprintln(os.Stderr, "usage: pqobfs-rotate -state DIR [-grace 720h]")
		os.Exit(2)
	}
	if err := obfs4.PQRotateKey(*state, *grace); err != nil {
		fmt.Fprintln(os.Stderr, "pqobfs-rotate:", err)
		os.Exit(1)
	}
	fmt.Println("rotated; restart the bridge and distribute its new bridge line")
}
