package token_test

import (
	"github.com/adharshmk96/goutils/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

var privateKey = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAb+BFeSALtM5FSb/OfDxzn9lUc31pL3Uu91EEs9g7WzdswLPZ9Vgr
6l4JHCSmP7/R6T+cjDwQmZzg6DpH8cWU8RugBwYFK4EEACOhgYkDgYYABAD9r39u
2bTnti+JhO+M390zdPepz7Of+Nn5p4103p2v3dF7mGubrMUBMy9qnlYrwGlDpnG4
0cvBnSvA9F0hqsE43QCHNsEqse+8PV/Eg5vB4sUg2v0QXyjahjJzc7lMQ4SCM89Z
IoMSQkPf37eSSlB/jfC0jq/H22gTPfEeItRJBJt4hQ==
-----END EC PRIVATE KEY-----
`

var publicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA/a9/btm057YviYTvjN/dM3T3qc+z
n/jZ+aeNdN6dr93Re5hrm6zFATMvap5WK8BpQ6ZxuNHLwZ0rwPRdIarBON0AhzbB
KrHvvD1fxIObweLFINr9EF8o2oYyc3O5TEOEgjPPWSKDEkJD39+3kkpQf43wtI6v
x9toEz3xHiLUSQSbeIU=
-----END PUBLIC KEY-----
`

func TestGenerateJWT(t *testing.T) {
	claims := jwt.MapClaims{
		"user": "test",
	}

	privateKey, err := token.LoadPrivateKey([]byte(privateKey))
	assert.NoError(t, err)
	publicKey, err := token.LoadPublicKey([]byte(publicKey))
	assert.NoError(t, err)

	jwtUtil := token.NewJwtUtil(token.JWTConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})

	jwtEncoded, err := jwtUtil.EncodeJWT(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtEncoded)

}

func TestDecodeJWT(t *testing.T) {

	privateKey, err := token.LoadPrivateKey([]byte(privateKey))
	assert.NoError(t, err)
	publicKey, err := token.LoadPublicKey([]byte(publicKey))
	assert.NoError(t, err)

	jwtUtil := token.NewJwtUtil(token.JWTConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})

	claims := jwt.MapClaims{
		"user": "test",
	}
	jwtEncoded, err := jwtUtil.EncodeJWT(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtEncoded)

	decodeToken, err := jwtUtil.DecodeJWT(jwtEncoded)
	assert.NoError(t, err)
	assert.NotNil(t, decodeToken)

	decodedValue := decodeToken.Claims.(jwt.MapClaims)["user"]
	assert.Equal(t, "test", decodedValue)

}

func TestLoadKeysFromPath(t *testing.T) {
	// make file ./private.pem
	privateKeyPath := "./private.pem"
	f, err := os.Create(privateKeyPath)
	assert.NoError(t, err)
	_, err = f.WriteString(privateKey)
	assert.NoError(t, err)
	f.Close()

	// make file ./public.pem
	publicKeyPath := "./public.pem"
	f, err = os.Create(publicKeyPath)
	assert.NoError(t, err)
	_, err = f.WriteString(publicKey)
	assert.NoError(t, err)
	f.Close()

	privateKey, err := token.LoadPrivateKeyFromPath(privateKeyPath)
	assert.NoError(t, err)
	assert.NotNil(t, privateKey)

	publicKey, err := token.LoadPublicKeyFromPath(publicKeyPath)
	assert.NoError(t, err)
	assert.NotNil(t, publicKey)

	jwtUtil := token.NewJwtUtil(token.JWTConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})

	claims := jwt.MapClaims{
		"user": "test",
	}
	jwtEncoded, err := jwtUtil.EncodeJWT(claims)
	assert.NoError(t, err)
	assert.NotEmpty(t, jwtEncoded)

	decodeToken, err := jwtUtil.DecodeJWT(jwtEncoded)
	assert.NoError(t, err)
	assert.NotNil(t, decodeToken)

	decodedValue := decodeToken.Claims.(jwt.MapClaims)["user"]
	assert.Equal(t, "test", decodedValue)

	// remove file
	err = os.Remove(privateKeyPath)
	assert.NoError(t, err)
	err = os.Remove(publicKeyPath)
	assert.NoError(t, err)
}

func TestExpiredJWT(t *testing.T) {
	claims := jwt.MapClaims{
		"user": "test",
		"exp":  time.Now().Add(-time.Hour).Unix(),
	}

	privateKey, err := token.LoadPrivateKey([]byte(privateKey))
	assert.NoError(t, err)
	publicKey, err := token.LoadPublicKey([]byte(publicKey))
	assert.NoError(t, err)

	jwtUtil := token.NewJwtUtil(token.JWTConfig{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
	})

	jwtEncoded, err := jwtUtil.EncodeJWT(claims)
	assert.NoError(t, err)

	decodeToken, err := jwtUtil.DecodeJWT(jwtEncoded)
	assert.Error(t, err)
	assert.ErrorIs(t, err, jwt.ErrTokenExpired)
	assert.Nil(t, decodeToken)

}
