package authn

import (
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
)

func TestJwtMiddleware_Gin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	var (
		ctx *gin.Context
		rec *httptest.ResponseRecorder
	)

	var (
		extractor *mockExtractor
		parser    *mockParser
		mw        *JwtMiddleware
	)

	reset := func() {
		rec = httptest.NewRecorder()
		ctx = gin.CreateTestContextOnly(rec, engine)

		extractor = &mockExtractor{}
		parser = &mockParser{}
		mw = NewJwtMiddleware(extractor, parser)
	}

	t.Run("responds with 401 by default", func(t *testing.T) {
		reset()
		mw.Gin(ctx)
		assert.Equal(t, 401, rec.Code)
	})

	t.Run("responds with 401 if JWT parsing failed", func(t *testing.T) {
		t.Run("with a validation error", func(t *testing.T) {
			reset()
			extractor.token = "invalid-token"
			parser.err = &jwt.ValidationError{}

			mw.Gin(ctx)
			assert.Equal(t, 401, rec.Code)
		})

		t.Run("with a wrapped validation error", func(t *testing.T) {
			reset()
			extractor.token = "invalid-token"
			parser.err = fmt.Errorf("wrapped: %w", &jwt.ValidationError{})

			mw.Gin(ctx)
			assert.Equal(t, 401, rec.Code)
		})

		t.Run("with some other error", func(t *testing.T) {
			reset()
			extractor.token = "invalid-token"
			parser.err = errors.New("some random error")

			mw.Gin(ctx)
			assert.Equal(t, 401, rec.Code)
		})
	})

	t.Run("responds with 401 if JWT is invalid", func(t *testing.T) {
		reset()
		extractor.token = "invalid-token"
		parser.token = &jwt.Token{
			Valid: false,
		}

		mw.Gin(ctx)
		assert.Equal(t, 401, rec.Code)
	})

	t.Run("responds with 200 if JWT is valid", func(t *testing.T) {
		reset()

		// we can mock any values here. the only important thing is that the token's Valid field is true.
		extractor.token = "invalid-token"
		parser.token = &jwt.Token{
			Valid: true,
		}

		mw.Gin(ctx)
		assert.Equal(t, 200, rec.Code)

		// assert ctx has the proper jwt object
		ctxJwt := GetCtxJwt(ctx)
		assert.NotNil(t, ctxJwt, "context has no jwt object")
		assert.Equal(t, parser.token, ctxJwt.Token, "jwt token is not the same as the one returned by the parser")
	})
}
