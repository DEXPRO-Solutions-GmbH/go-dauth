package authserver

import (
	"errors"
	"net/http"

	"github.com/DEXPRO-Solutions-GmbH/go-dauth/http/authn"
	"github.com/golang-jwt/jwt/v4"
)

// AuthServer is a http.Handler that validates authentication information on http.Request objects.
//
// Trusted requests are responded with a status 204 and additional headers containing decoded information about the request
// user, etc.
//
// Untrusted requests are responded with a status 401.
type AuthServer struct {
	stack *authn.AuthStack
}

func NewAuthServer(stack *authn.AuthStack) *AuthServer {
	return &AuthServer{stack: stack}
}

func (server *AuthServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	// Get authentication information from request
	tokenStr, err := server.stack.ExtractRequestToken(request)
	if err != nil {
		http.Error(writer, "extracting request token failed", 500)
		return
	}
	if tokenStr == "" {
		http.Error(writer, "no token on request found", 401)
		return
	}

	// Parse token string
	token, claims, err := server.stack.ParseToken(tokenStr)
	if err != nil {
		var validationErr *jwt.ValidationError
		if errors.As(err, &validationErr) {
			http.Error(writer, "auth token validation failed: "+err.Error(), http.StatusUnauthorized)
		} else {
			http.Error(writer, "parsing auth token failed:"+err.Error(), http.StatusUnauthorized)
		}
		return
	}

	// Validate the parsed token
	if !token.Valid {
		http.Error(writer, "token invalid", 401)
		return
	}

	// Token is trusted from here on

	// Set response headers for proxies etc.
	header := writer.Header()

	// Add decoded, claims
	headers := NewHeader(claims)
	headers.SetOn(header)

	writer.WriteHeader(204)
}
