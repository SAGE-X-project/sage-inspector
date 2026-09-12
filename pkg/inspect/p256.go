package inspect

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
)

func parseP256(raw []byte) (crypto.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}
