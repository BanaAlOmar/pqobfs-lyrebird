package mlkem_kemeleon

// vzeroupper is implemented in vzu_amd64.s.
//
//go:noescape
func vzeroupper()

// afterAVX must be called after every call into CIRCL's ML-KEM.
func afterAVX() { vzeroupper() }
