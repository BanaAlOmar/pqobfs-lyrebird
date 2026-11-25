//go:build pqobfs

package transports

import "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/obfs4"

func init() {
	extraTransports = append(extraTransports, new(obfs4.PQTransport))
}
