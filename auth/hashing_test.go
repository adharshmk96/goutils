package auth_test

import (
	"testing"

	"github.com/adharshmk96/goutils/auth"
	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	params := auth.DefaultParams
	hash, err := auth.HashPassword("auth", params)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	assert.NotEqual(t, "auth", hash)
}

func TestVerifyPasswordHash(t *testing.T) {
	params := auth.DefaultParams
	hash, err := auth.HashPassword("auth", params)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)

	match, err := auth.VerifyPasswordHash("auth", hash)
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = auth.VerifyPasswordHash("wrongpassword", hash)
	assert.NoError(t, err)
	assert.False(t, match)
}
