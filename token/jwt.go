package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"github.com/golang-jwt/jwt/v5"
	"os"
)

type JWTConfig struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

type JWTUtil struct {
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func NewJwtUtil(config JWTConfig) *JWTUtil {
	return &JWTUtil{
		privateKey: config.PrivateKey,
		publicKey:  config.PublicKey,
	}
}

var (
	ErrLoadingKey = errors.New("error loading key")
)

func LoadPrivateKeyFromPath(privateKeyPath string) (*ecdsa.PrivateKey, error) {
	content, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return LoadPrivateKey(content)
}

func LoadPrivateKey(content []byte) (*ecdsa.PrivateKey, error) {

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, ErrLoadingKey
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func LoadPublicKeyFromPath(publicKeyPath string) (*ecdsa.PublicKey, error) {
	content, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	return LoadPublicKey(content)
}

func LoadPublicKey(content []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(content)
	if block == nil {
		return nil, ErrLoadingKey
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, err
	}

	return publicKey, nil
}

func (jutil *JWTUtil) EncodeJWT(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	tokenString, err := token.SignedString(jutil.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (jutil *JWTUtil) DecodeJWT(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jutil.publicKey, nil
	})
	if err != nil {
		return nil, err
	}

	return token, nil
}
