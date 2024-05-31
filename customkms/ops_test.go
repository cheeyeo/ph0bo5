package customkms

import (
	"errors"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
	"github.com/stretchr/testify/assert"
)

type mockKMSClient struct {
	kmsiface.KMSAPI
	raiseErr error
}

func (m *mockKMSClient) GetPublicKey(*kms.GetPublicKeyInput) (*kms.GetPublicKeyOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.GetPublicKeyOutput{
		PublicKey: []byte("key content"),
	}
	return output, nil
}

func (m *mockKMSClient) Encrypt(*kms.EncryptInput) (*kms.EncryptOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.EncryptOutput{
		CiphertextBlob: []byte("ciphertext"),
	}
	return output, nil
}

func (m *mockKMSClient) Decrypt(*kms.DecryptInput) (*kms.DecryptOutput, error) {
	if m.raiseErr != nil {
		return nil, m.raiseErr
	}

	output := &kms.DecryptOutput{
		Plaintext: []byte("plaintext"),
	}
	return output, nil
}

func TestGetPublicKeyNotFound(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New(kms.ErrCodeNotFoundException),
	}
	res, err := GetPublicKey(mockSvc, "HSHSH")
	assert.Nil(t, res)
	assert.Equal(t, err, errors.New(kms.ErrCodeNotFoundException))
}

func TestGetPublicKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}
	res, err := GetPublicKey(mockSvc, "Valid Key")
	assert.Equal(t, res, []byte("key content"))
	assert.Nil(t, err)
}

func TestEncryptKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	err := EncryptKey(mockSvc, "XXX", []byte("this is some text"), "/tmp/target")
	_, err2 := os.Stat("/tmp/target")
	assert.Nil(t, err)
	assert.Nil(t, err2)
	os.Remove("/tmp/target")
}

func TestEncryptKeyError(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New(kms.ErrCodeNotFoundException),
	}

	err := EncryptKey(mockSvc, "XXX", []byte("this is some text"), "/tmp/target")
	_, err2 := os.Stat("/tmp/target")
	assert.NotNil(t, err)
	assert.NotNil(t, err2)
	os.Remove("/tmp/target")
}

func TestDecryptKey(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	os.WriteFile("/tmp/key.enc", []byte("some content"), 0644)
	res, err := DecryptKey(mockSvc, "keyid", "/tmp/key.enc")
	assert.Equal(t, []byte("plaintext"), res)
	assert.Nil(t, err)
	os.Remove("/tmp/key.enc")
}

func TestDecryptKeyFileNotFound(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: nil,
	}

	res, err := DecryptKey(mockSvc, "keyid", "/tmp/key.enc")
	assert.Nil(t, res)
	assert.NotNil(t, err)
}

func TestDecryptKeyFileKMSError(t *testing.T) {
	mockSvc := &mockKMSClient{
		raiseErr: errors.New(kms.ErrCodeNotFoundException),
	}

	os.WriteFile("/tmp/key.enc", []byte("some content"), 0644)
	res, err := DecryptKey(mockSvc, "keyid", "/tmp/key.enc")
	assert.Nil(t, res)
	assert.Equal(t, err, errors.New(kms.ErrCodeNotFoundException))
}
