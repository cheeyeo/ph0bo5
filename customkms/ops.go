package customkms

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

func GetPublicKey(client kmsiface.KMSAPI, keyID string) ([]byte, error) {
	// Gets the PublicKey from an Asymmetric key
	output, err := client.GetPublicKey(&kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})

	if err != nil {
		return nil, err
	}

	// output is GetPublicKeyOutput
	// Get the public key as byte array
	return output.PublicKey, nil
}

func EncryptKey(client kmsiface.KMSAPI, keyId string, source []byte, target string) error {
	// Encrypt the data
	result, err := client.Encrypt(&kms.EncryptInput{
		KeyId:               aws.String(keyId),
		Plaintext:           source,
		EncryptionAlgorithm: aws.String("RSAES_OAEP_SHA_256"),
	})

	if err != nil {
		return err
	}

	err = os.WriteFile(target, result.CiphertextBlob, 0644)
	if err != nil {
		return err
	}

	return nil
}

func DecryptKey(client kmsiface.KMSAPI, keyId string, encrypted string) ([]byte, error) {
	encFile, err := os.ReadFile(encrypted)
	if err != nil {
		return nil, err
	}

	result, err := client.Decrypt(&kms.DecryptInput{
		CiphertextBlob:      encFile,
		KeyId:               aws.String(keyId),
		EncryptionAlgorithm: aws.String("RSAES_OAEP_SHA_256"),
	})

	if err != nil {
		return nil, err
	}

	return result.Plaintext, nil
}
