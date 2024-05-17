package passwd_test

import (
	"testing"

	"github.com/adharshmk96/goutils/password"
	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	params := password.DefaultParams
	hash, err := password.HashPassword("password", params)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	assert.NotEqual(t, "password", hash)
}

func TestVerifyPasswordHash(t *testing.T) {
	params := password.DefaultParams
	hash, err := password.HashPassword("password", params)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	match, err := password.VerifyPasswordHash("password", hash)
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = password.VerifyPasswordHash("wrongpassword", hash)
	assert.NoError(t, err)
	assert.False(t, match)
}
