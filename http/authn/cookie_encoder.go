package authn

import (
	"encoding/base64"
	"net/http"
)

// CookieEncoder is a helper interface for types that are able to encode / decode cookie values.
//
// Usage of this type allows to use different encryption methods (or none) for cookies.
type CookieEncoder interface {
	EncodeCookie(cookie *http.Cookie) error
	DecodeCookie(cookie *http.Cookie) error
	Encode(val []byte) []byte
	Decode(val []byte) ([]byte, error)
}

// Base64CookieEncoder is an encoder which encodes values via base64.
type Base64CookieEncoder struct {
}

func NewBase64CookieEncoder() *Base64CookieEncoder {
	return &Base64CookieEncoder{}
}

func (u *Base64CookieEncoder) EncodeCookie(cookie *http.Cookie) error {
	outBase64 := u.Encode([]byte(cookie.Value))
	cookie.Value = string(outBase64)
	return nil
}

func (u *Base64CookieEncoder) DecodeCookie(cookie *http.Cookie) error {
	encrypted, err := u.Decode([]byte(cookie.Value))
	if err != nil {
		return err
	}
	cookie.Value = string(encrypted)
	return nil
}

func (u *Base64CookieEncoder) Encode(val []byte) []byte {
	outBase64 := base64.StdEncoding.EncodeToString(val)
	return []byte(outBase64)
}

func (u *Base64CookieEncoder) Decode(val []byte) ([]byte, error) {
	encrypted, err := base64.StdEncoding.DecodeString(string(val))
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}
