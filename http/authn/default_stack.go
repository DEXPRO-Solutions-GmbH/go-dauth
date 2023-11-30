package authn

import (
	"github.com/golang-jwt/jwt/v4"
	"net/http"
)

// AuthStack is responsible for performing authentication in our APIs.
type AuthStack struct {
	extractChain TokenExtractorChain
	keyfunc      jwt.Keyfunc
}

func NewDefaultAuthStack(trustedIssuerBaseUrl string, cookieName string) *AuthStack {
	jwksManager := NewJwksManager()

	keyfunc := NewKeycloakKeyfunc(trustedIssuerBaseUrl, jwksManager)

	extractor := NewTokenExtractorChain()
	extractor = extractor.Append(NewBearerHeaderTokenExtractor())
	extractor = extractor.Append(NewJwtCookieExtractor(cookieName, NewBase64CookieEncoder()))

	return &AuthStack{
		extractChain: extractor,
		keyfunc:      keyfunc,
	}
}

func (d *AuthStack) ExtractRequestToken(request *http.Request) (string, error) {
	return d.extractChain.ExtractRequestToken(request)
}

func (d *AuthStack) ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}
	if token, err := jwt.ParseWithClaims(tokenString, claims, d.keyfunc); err != nil {
		return nil, nil, err
	} else {
		return token, claims, nil
	}
}

func (d *AuthStack) ValidateToken(token *jwt.Token) (bool, error) {
	// The JWT library already has validated the token. We can simply return the already evaluated token.
	return token.Valid, nil
}

func (d *AuthStack) ToMiddleware() *JwtMiddleware {
	return &JwtMiddleware{
		extractor: d,
		parser:    d,
	}
}
