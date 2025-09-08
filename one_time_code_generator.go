package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
)

type OneTimeTokenGenerator interface {
	Generate() (plain string, stored string, err error)
	Compare(stored string, plain string) bool
}

type DefaultOneTimeCodeGenerator struct{}

type DefaultOneTimeSha512TokenGenerator struct {
	TokenSize int
}

func (g *DefaultOneTimeCodeGenerator) Generate() (string, string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", "", err
	}
	plain := fmt.Sprintf("%06d", n.Int64())
	sum := sha256.Sum256([]byte(plain))
	stored := base64.RawStdEncoding.EncodeToString(sum[:])
	return plain, stored, nil
}

func (g *DefaultOneTimeCodeGenerator) Compare(stored string, plain string) bool {
	want, err := base64.RawStdEncoding.DecodeString(stored)
	if err != nil {
		return false
	}
	got := sha256.Sum256([]byte(plain))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}

func (cg *DefaultOneTimeSha512TokenGenerator) Generate() (string, string, error) {
	if cg.TokenSize <= 0 {
		cg.TokenSize = 32
	}
	rawToken := make([]byte, cg.TokenSize)
	if _, err := io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", err
	}
	plain := base64.RawURLEncoding.EncodeToString(rawToken)
	hash := sha512.Sum512([]byte(plain))
	stored := base64.RawURLEncoding.EncodeToString(hash[:])
	return plain, stored, nil
}

func (cg *DefaultOneTimeSha512TokenGenerator) Compare(stored string, plain string) bool {
	want, err := base64.RawURLEncoding.DecodeString(stored) // Changed from RawStdEncoding to RawURLEncoding
	if err != nil {
		return false
	}
	got := sha512.Sum512([]byte(plain))
	return subtle.ConstantTimeCompare(got[:], want) == 1
}
