package authn

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const ctxKeyTokenObject = "dexp-serviceframework-access-token-jwt-struct"

// Jwt is a wrapper around a parsed JWT token and its claims.
type Jwt struct {
	TokenStr string
	Token    *jwt.Token
	Claims   *Claims
}

func newJwt(tokenStr string, token *jwt.Token, claims *Claims) *Jwt {
	return &Jwt{TokenStr: tokenStr, Token: token, Claims: claims}
}

// SetCtxJwtGin sets the JWT object in the given gin context.
func SetCtxJwtGin(ctx *gin.Context, obj *Jwt) {
	ctx.Set(ctxKeyTokenObject, obj)
}

// GetCtxJwt returns the JWT object from the given context. Returns nil if no value is found.
func GetCtxJwt(ctx context.Context) *Jwt {
	value := ctx.Value(ctxKeyTokenObject)
	if value == nil {
		return nil
	} else {
		return value.(*Jwt)
	}
}
