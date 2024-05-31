package crypto5

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateRandomString(t *testing.T) {
	res := GenerateRandomString(32)
	assert.Equal(t, 32, len(res))

	res = GenerateRandomString(16)
	assert.Equal(t, 16, len(res))
}
