//go:build corpus

// Corpus generator for the statistical evaluation (artifact/analysis).
//
//	CORPUS_DIR=/tmp/corpus CORPUS_N=10000 \
//	  go test -tags corpus -run TestCorpus -v ./internal/mlkem_kemeleon/
//
// Writes fixed-width binary files (records concatenated):
//
//	ek_raw_{gostd,circl}.bin       raw FIPS 203 encapsulation keys (1184 B)
//	ek_enc_{gostd,circl}.bin       Kemeleon representatives of accepted keys (1156 B)
//	ct_raw_{gostd,circl}.bin       raw FIPS 203 ciphertexts (1088 B)
//	ct_enc_{gostd,circl}.bin       Kemeleon representatives of accepted ciphertexts (1252 B)
//	ek_enc_kyberpy.bin             encodings of CORPUS_DIR/ek_raw_kyberpy.bin, if present
//	acceptance.json                single-attempt acceptance counts
package mlkem_kemeleon

import (
	"crypto/mlkem"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	mlkem768 "github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func corpusDir(t *testing.T) string {
	d := os.Getenv("CORPUS_DIR")
	if d == "" {
		d = "/tmp/corpus"
	}
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	return d
}

func corpusN() int {
	if n, err := strconv.Atoi(os.Getenv("CORPUS_N")); err == nil {
		return n
	}
	return 10000
}

type corpusWriter struct{ f *os.File }

func newCW(t *testing.T, dir, name string) *corpusWriter {
	f, err := os.Create(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return &corpusWriter{f}
}
func (w *corpusWriter) put(b []byte) { _, _ = w.f.Write(b) }
func (w *corpusWriter) close()       { _ = w.f.Close() }

func gostdEK(t *testing.T) ([]byte, *mlkem.DecapsulationKey768) {
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatal(err)
	}
	return dk.EncapsulationKey().Bytes(), dk
}

func circlEK(t *testing.T) []byte {
	pk, _, err := mlkem768.GenerateKeyPair(nil)
	if err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, mlkem768.PublicKeySize)
	pk.Pack(raw)
	return raw
}

func TestCorpus(t *testing.T) {
	dir := corpusDir(t)
	n := corpusN()
	acc := map[string][2]int{} // accepted, trials

	// Encapsulation keys.
	for _, gen := range []string{"gostd", "circl"} {
		rawW := newCW(t, dir, "ek_raw_"+gen+".bin")
		encW := newCW(t, dir, "ek_enc_"+gen+".bin")
		ctRawW := newCW(t, dir, "ct_raw_"+gen+".bin")
		ctEncW := newCW(t, dir, "ct_enc_"+gen+".bin")
		var ekAcc, ekTrials, ctAcc, ctTrials int
		nRaw, nEnc, nCtRaw, nCtEnc := 0, 0, 0, 0
		for nRaw < n || nEnc < n || nCtRaw < n || nCtEnc < n {
			var raw []byte
			if gen == "gostd" {
				raw, _ = gostdEK(t)
			} else {
				raw = circlEK(t)
			}
			if nRaw < n {
				rawW.put(raw)
				nRaw++
			}
			ekTrials++
			if enc, ok := encodeEK(raw); ok {
				ekAcc++
				if nEnc < n {
					encW.put(enc)
					nEnc++
				}
			}
			// One encapsulation per key (implementation-specific).
			var ct []byte
			if gen == "gostd" {
				ek, err := mlkem.NewEncapsulationKey768(raw)
				if err != nil {
					t.Fatal(err)
				}
				_, ct = ek.Encapsulate()
			} else {
				c, _, err := Encapsulate(raw)
				if err != nil {
					t.Fatal(err)
				}
				ct = c
			}
			if nCtRaw < n {
				ctRawW.put(ct)
				nCtRaw++
			}
			ctTrials++
			enc, ok, err := encodeCt(ct, nil)
			if err != nil {
				t.Fatal(err)
			}
			if ok {
				ctAcc++
				if nCtEnc < n {
					ctEncW.put(enc)
					nCtEnc++
				}
			}
		}
		rawW.close()
		encW.close()
		ctRawW.close()
		ctEncW.close()
		acc["ek_"+gen] = [2]int{ekAcc, ekTrials}
		acc["ct_"+gen] = [2]int{ctAcc, ctTrials}
		t.Logf("%s: EK accept %d/%d, CT accept %d/%d", gen, ekAcc, ekTrials, ctAcc, ctTrials)
	}

	// Encode an externally generated raw-key corpus (kyber-py), if present.
	if b, err := os.ReadFile(filepath.Join(dir, "ek_raw_kyberpy.bin")); err == nil {
		w := newCW(t, dir, "ek_enc_kyberpy.bin")
		a, tr := 0, 0
		for off := 0; off+RawEKLen <= len(b); off += RawEKLen {
			tr++
			if enc, ok := encodeEK(b[off : off+RawEKLen]); ok {
				a++
				w.put(enc)
			}
		}
		w.close()
		acc["ek_kyberpy"] = [2]int{a, tr}
		t.Logf("kyberpy: EK accept %d/%d", a, tr)
	}

	f, _ := os.Create(filepath.Join(dir, "acceptance.json"))
	_ = json.NewEncoder(f).Encode(acc)
	f.Close()
}
