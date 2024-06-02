// Example KMS test

package main

import (
	"crypto/aes"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"context"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/zenazn/pkcs7pad"

	"github.com/cheeyeo/ph0bo5/crypto5"
	"github.com/cheeyeo/ph0bo5/customkms"
)

func main() {
	getCertificateCmd := flag.NewFlagSet("download-cert", flag.ExitOnError)
	certLocation := getCertificateCmd.String("path", "", "Path to save the public cert")
	certKeyId := getCertificateCmd.String("alias", "", "KMS Key Alias to get public key from")

	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)
	encryptSource := encryptCmd.String("source", "", "Source of file to encrypt. --source <PATH TO FILE>")
	encryptTarget := encryptCmd.String("target", "", "Destination of encrypted file: --target <PATH TO FILE>")
	derPath := encryptCmd.String("cert-der", "", "--cert <PATH TO PUBLIC DER CERT>")

	decryptCmd := flag.NewFlagSet("decrypt", flag.ExitOnError)
	decryptSource := decryptCmd.String("source", "", "Source file to decrypt")
	decryptTarget := decryptCmd.String("target", "", "Path to save decrypted file")
	decryptKeyId := decryptCmd.String("alias", "", "KMS Key Alias to use")

	reEncryptCmd := flag.NewFlagSet("reencrypt", flag.ExitOnError)
	sourceKey := reEncryptCmd.String("sourcek", "", "Source key ID")
	destKey := reEncryptCmd.String("destk", "", "New dest key ID")
	reEncryptSource := reEncryptCmd.String("source", "", "Encrypted file to reencrypt")

	if len(os.Args) < 2 {
		fmt.Println("expected 'download-cert', 'encrypt', 'decrypt' or 'reencrypt' subcommands")
		os.Exit(1)
	}

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
		config.WithSharedConfigProfile(os.Getenv("AWS_PROFILE")),
		config.WithRegion(os.Getenv("AWS_REGION")),
	)

	if err != nil {
		log.Fatalf(err.Error())
	}

	svc := kms.NewFromConfig(cfg)

	switch os.Args[1] {
	case "reencrypt":
		reEncryptCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'reencrypt'")
		fmt.Println(" sourcek:", *sourceKey)
		fmt.Println(" destk:", *destKey)
		fmt.Println(" reencrypt source:", *reEncryptSource)

		enc, err := os.ReadFile(*reEncryptSource)
		if err != nil {
			log.Fatalf(err.Error())
		}

		err = customkms.ReEncryptKey(context.TODO(), svc, enc, *sourceKey, *destKey, *reEncryptSource)
		if err != nil {
			log.Fatalf(err.Error())
		}

	case "download-cert":
		getCertificateCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'download-cert'")
		fmt.Println(" path:", *certLocation)
		fmt.Println(" KMS Alias:", *certKeyId)

		publicKey, err := customkms.GetPublicKey(context.TODO(), svc, *certKeyId)
		if err != nil {
			log.Fatalf(err.Error())
		}

		err = os.WriteFile(*certLocation, publicKey, 0664)
		if err != nil {
			log.Fatalf(err.Error())
		}

		log.Printf("Public Key written to %s\n", *certLocation)
	case "encrypt":
		encryptCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'encrypt'")
		fmt.Println(" source:", *encryptSource)
		fmt.Println(" target:", *encryptTarget)
		fmt.Println(" public key (DER) path:", *derPath)

		if *derPath == "" {
			log.Fatalf("Public key cannot be blank. Please run download-cert.")
		}
		orig, err := os.ReadFile(*encryptSource)
		if err != nil {
			log.Fatalf(err.Error())
		}

		// Convert to base64 encoding so it works for both text and images?
		plainText := base64.StdEncoding.EncodeToString(orig)

		// Pad data to be in blocks of 16 else it won't work...
		data := pkcs7pad.Pad([]byte(plainText), 16)

		if len(data)%aes.BlockSize != 0 {
			log.Fatalf("Plaintext is not a multiple of the block size")
		}

		// Generate Random AES 32 byte / 256 bit symmetric key for local encryption
		keyText := crypto5.GenerateRandomString(32)
		keyByte := []byte(keyText)

		// Encrypt file using random key
		cipherText := crypto5.EncryptWithAES(keyByte, string(data))

		// Save encrypted file
		err = os.WriteFile(*encryptTarget, []byte(cipherText), 0664)
		if err != nil {
			log.Fatalf(err.Error())
		}

		derData, err := os.ReadFile(*derPath)
		if err != nil {
			log.Fatalf(err.Error())
		}
		publicKey, err := crypto5.ConvertDERToRSA(derData)
		if err != nil {
			log.Fatalf(err.Error())
		}

		ciphertext, err := crypto5.EncryptWithRSA(publicKey, keyByte, nil)
		if err != nil {
			log.Fatalf(err.Error())
		}
		dir := filepath.Dir(*encryptTarget)
		base := filepath.Base(*encryptTarget)
		ext := filepath.Ext(base)
		prefix := strings.TrimSuffix(base, ext)

		newPath := []string{prefix, "key"}
		newPath2 := strings.Join(newPath, ".")
		target_key_path := filepath.Join(dir, newPath2)

		err = os.WriteFile(target_key_path, ciphertext, 0664)
		if err != nil {
			log.Fatalf(err.Error())
		}

	case "decrypt":
		decryptCmd.Parse(os.Args[2:])
		fmt.Println("subcommand 'decrypt'")
		fmt.Println(" source:", *decryptSource)
		fmt.Println(" target:", *decryptTarget)
		fmt.Println(" KMS Alias:", *decryptKeyId)

		// Decrypt the encrypted private key using KMS decrypt
		// Encrypted file of path <orig file nam>.key
		dir := filepath.Dir(*decryptSource)
		base := filepath.Base(*decryptSource)
		ext := filepath.Ext(base)
		prefix := strings.TrimSuffix(base, ext)

		newPath := []string{prefix, "key"}
		newPath2 := strings.Join(newPath, ".")
		target_key_path := filepath.Join(dir, newPath2)

		keyByte, err := customkms.DecryptKey(context.TODO(), svc, *decryptKeyId, target_key_path)
		if err != nil {
			log.Fatalf(err.Error())
		}

		cipherText, err := os.ReadFile(*decryptSource)
		if err != nil {
			log.Fatalf(err.Error())
		}

		plain, err := crypto5.DecryptWithAES(keyByte, string(cipherText))
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
