package customkms

import (
	"errors"
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
