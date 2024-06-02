package customkms

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/stretchr/testify/assert"
)

type mockKMSClient struct {
	raiseErr error
}

func (m *mockKMSClient) GetPublicKey(ctx context.Context, params *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.GetPublicKeyOutput{
		PublicKey: []byte("key content"),
	}
	return output, nil
}

func (m *mockKMSClient) Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.EncryptOutput{
		CiphertextBlob: []byte("ciphertext"),
	}
	return output, nil
}

func (m *mockKMSClient) Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.DecryptOutput{
		Plaintext: []byte("plaintext"),
	}
	return output, nil
}

func (m *mockKMSClient) ReEncrypt(ctx context.Context, params *kms.ReEncryptInput, optFns ...func(*kms.Options)) (*kms.ReEncryptOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.ReEncryptOutput{
		CiphertextBlob: []byte("ciphertext"),
	}
	return output, nil
}

func TestGetPublicKeyNotFound(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New("key not found"),
	}
	res, err := GetPublicKey(context.TODO(), mockSvc, "HSHSH")
	assert.Nil(t, res)
	assert.Equal(t, err, errors.New("key not found"))
}

func TestGetPublicKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}
	res, err := GetPublicKey(context.TODO(), mockSvc, "Valid Key")
	assert.Equal(t, res, []byte("key content"))
	assert.Nil(t, err)
}

func TestEncryptKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	err := EncryptKey(context.TODO(), mockSvc, "XXX", []byte("this is some text"), "/tmp/target")
	_, err2 := os.Stat("/tmp/target")
	assert.Nil(t, err)
	assert.Nil(t, err2)
	os.Remove("/tmp/target")
}

func TestEncryptKeyError(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New("key not found"),
	}

	err := EncryptKey(context.TODO(), mockSvc, "XXX", []byte("this is some text"), "/tmp/target")
	_, err2 := os.Stat("/tmp/target")
	assert.Equal(t, err, errors.New("key not found"))
	assert.NotNil(t, err)
	assert.NotNil(t, err2)
	os.Remove("/tmp/target")
}

func TestDecryptKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	os.WriteFile("/tmp/key.enc", []byte("some content"), 0644)
	res, err := DecryptKey(context.TODO(), mockSvc, "keyid", "/tmp/key.enc")
	assert.Equal(t, []byte("plaintext"), res)
	assert.Nil(t, err)
	os.Remove("/tmp/key.enc")
}

func TestDecryptKeyFileNotFound(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	res, err := DecryptKey(context.TODO(), mockSvc, "keyid", "/tmp/key.enc")
	assert.Nil(t, res)
	assert.NotNil(t, err)
}

func TestDecryptKeyFileKMSError(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New("key not found"),
	}

	os.WriteFile("/tmp/key.enc", []byte("some content"), 0644)
	res, err := DecryptKey(context.TODO(), mockSvc, "keyid", "/tmp/key.enc")
	assert.Nil(t, res)
	assert.Equal(t, err.Error(), "key not found")
}

func TestReEncryptKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	err := ReEncryptKey(context.TODO(), mockSvc, []byte("data"), "alias/SOURCE", "alias/TARGET", "/tmp/key.enc")
	assert.Nil(t, err)
	os.Remove("/tmp/key.enc")
}

func TestReEncryptKeyError(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New("key not found"),
	}

	err := ReEncryptKey(context.TODO(), mockSvc, []byte("data"), "alias/SOURCE", "alias/TARGET", "/tmp/key.enc")
	assert.NotNil(t, err)
	assert.Equal(t, err.Error(), "key not found")
	os.Remove("/tmp/key.enc")
}
