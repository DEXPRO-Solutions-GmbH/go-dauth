package authn

import (
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

type TokenExtractor interface {
	// ExtractRequestToken tries to extract an access token as plain string from the given request.
	//
	// If no token is found, an empty string and no error must be returned
	ExtractRequestToken(request *http.Request) (string, error)
}

type TokenParser interface {
	// ParseToken parses a string to a jwt.Token. Parsed Claims must also be returned. This ensures that the correct
	// claims type is used.
	//
	// This method will either return an error or a parsed token.
	ParseToken(tokenString string) (*jwt.Token, *Claims, error)
}
