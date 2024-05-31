package crypto5

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// Convert AWS KMS PUBLIC KEY to RSA Public Key
func ConvertDERToRSA(data []byte) (*rsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("Public key is of type RSA")
		return pub, nil
	default:
		return nil, errors.New("invalid RSA Public key")
	}
}

func EncryptWithRSA(public_key *rsa.PublicKey, data []byte, label []byte) ([]byte, error) {
	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, public_key, data, label)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}
