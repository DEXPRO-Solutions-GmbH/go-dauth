package authn

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// JwtMiddleware is responsible for extraction, parsing and validation of JWTs from requests.
type JwtMiddleware struct {
	extractor TokenExtractor
	parser    TokenParser
}

func NewJwtMiddleware(extractor TokenExtractor, parser TokenParser) *JwtMiddleware {
	j := &JwtMiddleware{extractor: extractor, parser: parser}
	return j
}

func (mw *JwtMiddleware) Gin(ctx *gin.Context) {
	request := ctx.Request
	writer := ctx.Writer

	tokenStr, err := mw.extractor.ExtractRequestToken(request)
	if err != nil || tokenStr == "" {
		http.Error(writer, ErrAuthTokenMissing.Error(), http.StatusUnauthorized)
		ctx.Abort()
		return
	}

	token, claims, err := mw.parser.ParseToken(tokenStr)
	if err != nil {
		var validationErr *jwt.ValidationError
		if errors.As(err, &validationErr) {
			http.Error(writer, "auth token validation failed: "+err.Error(), http.StatusUnauthorized)
			ctx.Abort()
		} else {
			http.Error(writer, "parsing auth token failed:"+err.Error(), http.StatusUnauthorized)
			ctx.Abort()
		}
		return
	}

	if !token.Valid {
		http.Error(writer, "token invalid", http.StatusUnauthorized)
		ctx.Abort()
		return
	}

	// Cache validation data so that further requests with the same token are faster.
	// TODO: Implement token / validation caching if desired (must be configurable)

	// Add token to request context

	obj := newJwt(tokenStr, token, claims)
	SetCtxJwtGin(ctx, obj)
}
