package customaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
)

func checkErr(err error) {
	if err != nil {
		fmt.Printf("Error is %+v\n", err)
		log.Fatal("ERROR:", err)
	}
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

func Decrypt(keyByte []byte, cipherText string) string {
	cipherTextByte, _ := hex.DecodeString(cipherText)

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
	return string(cipherTextByte[:])
}
