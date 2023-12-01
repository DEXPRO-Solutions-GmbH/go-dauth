package authserver

import (
	"context"
	"fmt"
	"net/http"

	"github.com/DEXPRO-Solutions-GmbH/go-dauth/http/authn"
	"github.com/gin-gonic/gin"
)

const (
	ctxKeyHeader = "Dexp-Authserver-Parsed-Headers"
)

// GetContextAuthHeader tries to get a Header object from the given context.
//
// Returns nil if no value is found.
func GetContextAuthHeader(ctx context.Context) *Header {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		header, exists := ginCtx.Get(ctxKeyHeader)
		if !exists {
			return nil
		}
		return header.(*Header)
	}

	header := ctx.Value(ctxKeyHeader)
	if header == nil {
		return nil
	}
	return header.(*Header)
}

// MustGetContextAuthHeader is like GetContextAuthHeader but panics if no value
// is found.
func MustGetContextAuthHeader(ctx context.Context) *Header {
	header := GetContextAuthHeader(ctx)
	if header == nil {
		panic("missing auth header on context object. should probably be added my some middleware")
	}
	return header
}

// MustGetContextAuthClaims is like MustGetContextAuthHeader but returns the claims
// from Header.
func MustGetContextAuthClaims(ctx context.Context) *authn.Claims {
	header := MustGetContextAuthHeader(ctx)
	return header.Claims
}

func SetContextAuthHeader(ctx context.Context, header *Header) context.Context {
	if ginCtx, ok := ctx.(*gin.Context); ok {
		ginCtx.Set(ctxKeyHeader, header)
		return ginCtx
	}

	return context.WithValue(ctx, ctxKeyHeader, header)
}

// NewHeaderParserMiddleware returns a middleware that parses the auth headers into a Header object and adds it to the request
// context. Use GetContextAuthHeader to retrieve the parsed header from the context.
//
// Deprecated: We generally want to use gin as our web framework. Maintaining both middlewares
// means more work. Please migrate towards GinHeaderParserMiddleware.
func NewHeaderParserMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		header, err := ParseHeader(request.Header)
		if err != nil {
			http.Error(writer, fmt.Sprintf("parsing auth headers failed: %s", err), http.StatusUnauthorized)
			return
		}

		request = request.WithContext(SetContextAuthHeader(request.Context(), header))
		next.ServeHTTP(writer, request)
	})
}

// GinHeaderParserMiddleware is a gin middleware that behaves like the middleware returned from NewHeaderParserMiddleware.
func GinHeaderParserMiddleware(ctx *gin.Context) {
	header, err := ParseHeader(ctx.Request.Header)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, fmt.Errorf("parsing auth headers failed: %w", err))
		return
	}

	SetContextAuthHeader(ctx, header)
}
