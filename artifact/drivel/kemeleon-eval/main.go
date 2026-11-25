// Command kemeleon-eval encodes ML-KEM ciphertexts from Go's crypto/mlkem
// with Drivel's Kemeleon (non-rejection) ciphertext encoder, checks that
// every encoding decodes back to the original ciphertext, and writes the
// encodings to <outdir>/drivel_<param>.bin for the wire-image tests.
//
// Usage: go run ./cmd/kemeleon-eval <outdir> [n]
package main

import (
	"bytes"
	"crypto/mlkem"
	"fmt"
	"os"
	"strconv"

	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/cryptofactory/encoding_kemeleon"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/internal/kems"
)

// paramName satisfies kems.KeyEncapsulationMechanism; the encoder's Init
// only reads Name() to select the parameter set.
type paramName string

func (p paramName) Name() string          { return string(p) }
func (paramName) LengthPublicKey() int    { return 0 }
func (paramName) LengthPrivateKey() int   { return 0 }
func (paramName) LengthCiphertext() int   { return 0 }
func (paramName) LengthSharedSecret() int { return 0 }
func (paramName) KeyGen() *kems.Keypair   { return nil }
func (paramName) Encaps(kems.PublicKey) (kems.Ciphertext, kems.SharedSecret, error) {
	return kems.Ciphertext{}, kems.SharedSecret{}, fmt.Errorf("not used")
}
func (paramName) Decaps(kems.PrivateKey, kems.Ciphertext) (kems.SharedSecret, error) {
	return kems.SharedSecret{}, fmt.Errorf("not used")
}

func run(outdir, name string, n int, encaps func() []byte) error {
	enc := &encoding_kemeleon.KemeleonEncoder{}
	enc.Init(paramName(name))
	L := enc.LengthObfuscatedCiphertext()
	var out bytes.Buffer
	for i := 0; i < n; i++ {
		ct := encaps()
		obf := make([]byte, L)
		if !enc.EncodeCiphertext(obf, ct) {
			return fmt.Errorf("%s: encode failed at %d", name, i)
		}
		back := make([]byte, len(ct))
		enc.DecodeCiphertext(back, obf)
		if !bytes.Equal(back, ct) {
			return fmt.Errorf("%s: round trip mismatch at %d", name, i)
		}
		out.Write(obf)
	}
	if err := os.WriteFile(outdir+"/drivel_"+name+".bin", out.Bytes(), 0o644); err != nil {
		return err
	}
	fmt.Printf("%s: %d encodings of %d bytes, every round trip exact\n", name, n, L)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: kemeleon-eval <outdir> [n]")
		os.Exit(2)
	}
	outdir, n := os.Args[1], 10000
	if len(os.Args) > 2 {
		n, _ = strconv.Atoi(os.Args[2])
	}
	dk768, _ := mlkem.GenerateKey768()
	ek768 := dk768.EncapsulationKey()
	dk1024, _ := mlkem.GenerateKey1024()
	ek1024 := dk1024.EncapsulationKey()
	for _, c := range []struct {
		name string
		f    func() []byte
	}{
		{"ML-KEM-768", func() []byte { _, ct := ek768.Encapsulate(); return ct }},
		{"ML-KEM-1024", func() []byte { _, ct := ek1024.Encapsulate(); return ct }},
	} {
		if err := run(outdir, c.name, n, c.f); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
