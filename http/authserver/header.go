package authserver

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/DEXPRO-Solutions-GmbH/go-dauth/http/authn"
)

const (
	// defaultHeaderPrefix is used to prefix all headers set by AuthServer
	defaultHeaderPrefix = "Dexp-Authserver-"
	headerJwtPlain      = "Jwt-Plain"
)

// Header are the headers set by an AuthServer after a request has successfully been authenticated.
type Header struct {
	Claims *authn.Claims
}

func NewHeader(claims *authn.Claims) *Header {
	return &Header{Claims: claims}
}

// ParseHeader takes a http.Header and tries to parse Header from it. Use this function if you receive requests
// that are being authenticated by an AuthServer.
//
// This will return an error if any non-optional header are missing.
//
// When parsing, Header.Claims will not be validated but only parsed.
func ParseHeader(from http.Header) (*Header, error) {
	headerPrefix := defaultHeaderPrefix
	claimsStr := from.Get(fmt.Sprintf("%s%s", headerPrefix, headerJwtPlain))

	if claimsStr == "" {
		return nil, errors.New("missing jwt plain")
	}

	var claims authn.Claims
	if err := json.Unmarshal([]byte(claimsStr), &claims); err != nil {
		return nil, errors.New("parsing claims failed")
	}

	return NewHeader(&claims), nil
}

func (h *Header) SetOn(header http.Header) {
	headerPrefix := defaultHeaderPrefix
	claimsStr, err := json.Marshal(h.Claims)
	if err != nil {
		panic(fmt.Errorf("marshaling claims to json failed: %v", err))
	}
	header.Set(fmt.Sprintf("%s%s", headerPrefix, headerJwtPlain), string(claimsStr))
}
