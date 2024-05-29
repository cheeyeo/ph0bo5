// Example KMS test

package main

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/zenazn/pkcs7pad"

	"github.com/cheeyeo/ph0bo5/customaes"
	"github.com/cheeyeo/ph0bo5/customkms"
)

func main() {
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encryptSource := encryptCmd.String("source", "", "source")
	encryptTarget := encryptCmd.String("target", "", "target")

	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decryptSource := decryptCmd.String("source", "", "source")
	decryptTarget := decryptCmd.String("target", "", "target")

	if len(os.Args) < 2 {
		fmt.Println("expected 'encrypt' or 'decrypt' subcommands")
		os.Exit(1)
	}

	sess, err := session.NewSessionWithOptions(session.Options{
		Profile: os.Getenv("AWS_PROFILE"),
		Config: aws.Config{
			Region: aws.String(os.Getenv("AWS_REGION")),
		},
	})

	if err != nil {
		log.Fatalf(err.Error())
		os.Exit(1)
	}

	// Specify ARN or ALIAS of KMS KEY
	keyId := os.Getenv("KEY_ID")
	// fmt.Println(keyId)
	if len(keyId) == 0 {
		log.Fatalf("Key ID cannot be blank! Check your .env file")
		os.Exit(1)
	}

	svc := kms.New(sess)

	switch os.Args[1] {
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'encrypt'")
		fmt.Println("  source:", *encryptSource)
		fmt.Println("  target:", *encryptTarget)

		orig, err := os.ReadFile(*encryptSource)
		if err != nil {
			log.Fatal(err.Error())
		}

		// Convert to base64 encoding so it works for both text and images?
		plainText := base64.StdEncoding.EncodeToString(orig)

		// Pad data to be in blocks of 16 else it won't work...
		data := pkcs7pad.Pad([]byte(plainText), 16)

		if len(data)%aes.BlockSize != 0 {
			panic("Plaintext is not a multiple of the block size")
		}

		// Generate Random AES 32 byte / 256 bit symmetric key for local encryption
		keyText := make([]byte, 32) //generate a random 32 byte key for AES-256
		if _, err := rand.Read(keyText); err != nil {
			log.Fatalf(err.Error())
		}
		keyByte := []byte(keyText)

		// Encrypt file using random key
		cipherText := customaes.Encrypt(keyByte, string(data))

		// Save encrypted file
		err = os.WriteFile(*encryptTarget, []byte(cipherText), 0664)
		if err != nil {
			log.Fatalf(err.Error())
		}

		// Encrypt random key using openssl
		err = customkms.EncryptKey(svc, keyId, keyByte, "key.b64.enc")
		if err != nil {
			log.Fatalf(err.Error())
		}
	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'decrypt'")
		fmt.Println("  source:", *decryptSource)
		fmt.Println("  target:", *decryptTarget)

		// Decrypt the encrypted private key using KMS decrypt
		err = customkms.DecryptKey(svc, keyId, "key.b64.enc", "decrypted_key.b64")
		if err != nil {
			log.Fatal(err.Error())
		}

		// Decrypt the encrypted file
		keyByte, err := os.ReadFile("decrypted_key.b64")
		if err != nil {
			log.Fatal(err.Error())
		}

		cipherText, err := os.ReadFile(*decryptSource)
		if err != nil {
			log.Fatalf(err.Error())
		}

		plain, err := customaes.Decrypt(keyByte, string(cipherText))
		if err != nil {
			log.Fatalf(err.Error())
		}
		// Need to base64 decode and then save it
		decoded, _ := base64.StdEncoding.DecodeString(plain)
		err = os.WriteFile(*decryptTarget, decoded, 0664)
		if err != nil {
			log.Fatalf(err.Error())
		}

		log.Printf("File written to %s\n", *decryptTarget)
	}
}
