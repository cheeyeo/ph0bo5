package customaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
)

func checkErr(err error) {
	if err != nil {
		fmt.Printf("Error is %+v\n", err)
		log.Fatalf(err.Error())
	}
}

func GenerateRandomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	// return base64.RawURLEncoding.EncodeToString(b)
	return string(b)
}

func Encrypt(keyByte []byte, plainText string) string {

	plainTextByte := []byte(plainText)

	// GET CIPHER BLOCK USING KEY
	block, err := aes.NewCipher(keyByte)
	checkErr(err)

	cipherTextByte := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherTextByte[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	// GET CTR
	ctr := cipher.NewCTR(block, iv)

	// ENCRYPT DATA
	ctr.XORKeyStream(cipherTextByte[aes.BlockSize:], plainTextByte)

	// RETURN HEX
	cipherText := hex.EncodeToString(cipherTextByte)
	return cipherText
}

func Decrypt(keyByte []byte, cipherText string) (string, error) {
	cipherTextByte, err := hex.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	// CHECK cipherTextByte
	// CBC mode always works in whole blocks.
	if len(cipherTextByte)%aes.BlockSize != 0 {
		panic("cipherTextByte is not a multiple of the block size")
	}

	// GET CIPHER BLOCK USING KEY
	block, err := aes.NewCipher(keyByte)
	checkErr(err)

	iv := cipherTextByte[:aes.BlockSize]
	cipherTextByte = cipherTextByte[aes.BlockSize:]

	// GET CTR
	ctr := cipher.NewCTR(block, iv)

	// DECRYPT DATA
	// XORKeyStream can work in-place if the two arguments are the same.
	ctr.XORKeyStream(cipherTextByte, cipherTextByte)

	// RETURN STRING
	return string(cipherTextByte[:]), nil
}

type InvalidRSAPublicKeyError struct{}

func (e InvalidRSAPublicKeyError) Error() string {
	return "Invalid RSA Public key"
}

// Decrypt AWS KMS PUBLIC KEY to RSA Public Key
func ConvertDERToRSA(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(data)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		fmt.Println("Public key is of type RSA")
		return pub, nil
	default:
		return nil, InvalidRSAPublicKeyError{}
	}
}

func EncryptWithRSA(public_key *rsa.PublicKey, data []byte, label []byte) ([]byte, error) {
	// crypto/rand.Reader is a good source of entropy for randomizing the
	// encryption function.
	rng := rand.Reader

	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, public_key, data, label)
	if err != nil {
		return []byte(nil), err
	}

	// fmt.Printf("Ciphertext: %x\n", ciphertext)
	return ciphertext, nil
}
