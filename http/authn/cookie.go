package authn

import (
	"errors"
	"net/http"
)

// AccessTokenCookieName returns a standard cookie name to be used for cookies carrying access tokens.
func AccessTokenCookieName(prefix string) string {
	return prefix + "-at"
}

// GetAccessTokenCookie retrieves the access token cookie from the request.
func GetAccessTokenCookie(request *http.Request, prefix string) (*http.Cookie, error) {
	cookie, err := request.Cookie(AccessTokenCookieName(prefix))
	if err != nil {
		return nil, errors.New("missing access token cookie")
	}

	// TODO: Add encoder

	return cookie, nil
}
