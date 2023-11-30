package authn

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJwtMiddleware_Gin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	extractor := newMockExtractor()
	parser := newMockParser()

	var (
		ctx *gin.Context
		rec *httptest.ResponseRecorder
	)

	setup := func() {
		rec = httptest.NewRecorder()
		ctx = gin.CreateTestContextOnly(rec, engine)
	}

	t.Run("request with no token", func(t *testing.T) {
		t.Run("responds with 401 by default", func(t *testing.T) {
			setup()
			mw := NewJwtMiddleware(extractor, parser)
			mw.Gin(ctx)
			assert.Equal(t, 401, rec.Code)
		})
	})
}
