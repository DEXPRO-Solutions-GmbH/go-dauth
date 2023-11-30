package authn

import (
	"errors"
	"net/http"
	"strings"
)

// BearerHeaderTokenExtractor extracts tokens from the Authorization header. It expects the token to be prefixed with "Bearer ".
type BearerHeaderTokenExtractor struct{}

func NewBearerHeaderTokenExtractor() *BearerHeaderTokenExtractor {
	return &BearerHeaderTokenExtractor{}
}

func (d *BearerHeaderTokenExtractor) ExtractRequestToken(request *http.Request) (string, error) {
	authHeader := request.Header.Get("Authorization")
	authHeader = strings.TrimPrefix(authHeader, "bearer ")
	authHeader = strings.TrimPrefix(authHeader, "Bearer ")
	authHeader = strings.TrimPrefix(authHeader, "BEARER ")
	return authHeader, nil
}

// JwtCookieExtractor extracts tokens from a cookie.
type JwtCookieExtractor struct {
	cookieName string
	encoder    CookieEncoder
}

// NewJwtCookieExtractor creates a new JwtCookieExtractor.
//
// If encoder is nil, the cookie value will be returned as is.
func NewJwtCookieExtractor(cookieName string, encoder CookieEncoder) *JwtCookieExtractor {
	return &JwtCookieExtractor{cookieName: cookieName, encoder: encoder}
}

func (j *JwtCookieExtractor) ExtractRequestToken(request *http.Request) (string, error) {
	cookie, err := request.Cookie(j.cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return "", nil
		} else {
			return "", err
		}
	}

	if j.encoder == nil {
		return cookie.Value, nil
	}

	decoded, err := j.encoder.Decode([]byte(cookie.Value))
	if err != nil {
		return "", err
	}

	return string(decoded), err
}
