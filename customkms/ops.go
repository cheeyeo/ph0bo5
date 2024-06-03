package customkms

import (
	"context"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KMSApi interface {
	GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)

	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)

	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)

	ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, optFns ...func(*kms.Options)) (*kms.ReEncryptOutput, error)
}

func ReEncryptKey(ctx context.Context, api KMSApi, data []byte, sourceKeyAlias string, destKeyAlias string, target string) error {
	result, err := api.ReEncrypt(ctx, &kms.ReEncryptInput{
		CiphertextBlob:                 data,
		DestinationKeyId:               aws.String(destKeyAlias),
		SourceKeyId:                    aws.String(sourceKeyAlias),
		DestinationEncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
		SourceEncryptionAlgorithm:      types.EncryptionAlgorithmSpecRsaesOaepSha256,
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

func GetPublicKey(ctx context.Context, api KMSApi, keyID string) ([]byte, error) {
	// Gets the PublicKey from an Asymmetric key
	output, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(keyID),
	})

	if err != nil {
		return nil, err
	}

	// output is GetPublicKeyOutput
	// Get the public key as byte array
	return output.PublicKey, nil
}

func EncryptKey(ctx context.Context, api KMSApi, keyId string, source []byte, target string) error {
	// Encrypt the data
	result, err := api.Encrypt(ctx, &kms.EncryptInput{
		KeyId:               aws.String(keyId),
		Plaintext:           source,
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
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

func DecryptKey(ctx context.Context, api KMSApi, keyId string, encrypted string) ([]byte, error) {
	encFile, err := os.ReadFile(encrypted)
	if err != nil {
		return nil, err
	}

	result, err := api.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:      encFile,
		KeyId:               aws.String(keyId),
		EncryptionAlgorithm: types.EncryptionAlgorithmSpecRsaesOaepSha256,
	})

	if err != nil {
		return nil, err
	}

	return result.Plaintext, nil
}
