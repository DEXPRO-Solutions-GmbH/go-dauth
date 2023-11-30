package authn

import (
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"strings"
)

// NewKeycloakKeyfunc returns a keyfunc that fetches JWKS instances from a single trusted Keycloak server.
//
// Callers of this func have to supply a JwksManager which is responsible for fetching and caching the public keys used for
// token signature validation.
//
// The returned keyfunc inspects the tokens "iss" (issuer) claim to determine what key set to use.
func NewKeycloakKeyfunc(trustedIssuerBaseUrl string, jwksManager *JwksManager) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		// Each Keycloak realm holds its own keys
		// Therefore we must lookup the issuer to know what key to use

		claims, ok := token.Claims.(*Claims)
		if !ok {
			return nil, errors.New("parsed token claims are not of type *Claims")
		}

		// Reject untrusted issuers
		issuer := claims.Issuer
		if !strings.HasPrefix(issuer, trustedIssuerBaseUrl) {
			return nil, errors.New("token has been issued by non-trusted issuer")
		}

		// Get keys
		jwksUrl := fmt.Sprintf("%s/protocol/openid-connect/certs", issuer)
		kf, err := jwksManager.GetKeyfuncForJwksURL(jwksUrl)
		if err != nil {
			return nil, err
		}

		return kf(token)
	}
}
