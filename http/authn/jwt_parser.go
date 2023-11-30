package authn

import (
	"github.com/golang-jwt/jwt/v4"
)

// UnsecureJwtParser parses a JWT token without validating its signature. Do not use this type in production!
type UnsecureJwtParser struct{}

func NewUnsecureJwtParser() *UnsecureJwtParser {
	return &UnsecureJwtParser{}
}

func (u *UnsecureJwtParser) ParseToken(str string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, _, err := jwt.NewParser().ParseUnverified(str, claims)

	token.Valid = true

	if err != nil {
		return nil, nil, err
	} else {
		return token, claims, nil
	}
}
