package authserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DEXPRO-Solutions-GmbH/go-dauth/http/authn"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestMiddlewareGin ensures that this packages middleware is compatible with gin.
func TestMiddlewareGin(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()

	t.Run("rejects request without header", func(t *testing.T) {
		// setup
		rec := httptest.NewRecorder()
		ctx := gin.CreateTestContextOnly(rec, engine)
		ctx.Request, _ = http.NewRequest("GET", "/", nil)
		// invoke middleware
		GinHeaderParserMiddleware(ctx)
		// assert
		res := rec.Result()
		require.Equal(t, 401, res.StatusCode)
	})

	t.Run("authenticates proper request", func(t *testing.T) {
		// setup
		rec := httptest.NewRecorder()
		ctx := gin.CreateTestContextOnly(rec, engine)
		ctx.Request, _ = http.NewRequest("GET", "/", nil)
		setAuthHeaders(ctx.Request.Header)
		// invoke middleware
		GinHeaderParserMiddleware(ctx)

		// assert
		res := rec.Result()
		require.Equal(t, 200, res.StatusCode)

		t.Run("ctx holds expected header value", func(t *testing.T) {
			value := ctx.Value(ctxKeyHeader)
			require.NotNil(t, value)
			require.IsType(t, &Header{}, value)
			require.Equal(t, uuid.MustParse(testTenantId), value.(*Header).Claims.TenantId)
		})

		t.Run("header can be retrieved via getter", func(t *testing.T) {
			value := GetContextAuthHeader(ctx)
			require.NotNil(t, value)
			require.IsType(t, &Header{}, value)
			require.Equal(t, uuid.MustParse(testTenantId), value.Claims.TenantId)
		})

		t.Run("header can be retrieved via must-getter", func(t *testing.T) {
			value := MustGetContextAuthHeader(ctx)
			require.NotNil(t, value)
			require.IsType(t, &Header{}, value)
			require.Equal(t, uuid.MustParse(testTenantId), value.Claims.TenantId)
		})
	})
}

// testTenantId is a random uuid used for testing.
const testTenantId = "edcf7043-e534-4a24-97ad-10dc2faf0281"

// setAuthHeaders sets the authserver.Header on the given header object.
//
// This allows you to mock authentication.
func setAuthHeaders(header http.Header) {
	tenantName := "test"
	tenantId := uuid.MustParse(testTenantId)

	authHeader := NewHeader(&authn.Claims{
		TenantId:   tenantId,
		TenantName: tenantName,
	})

	authHeader.SetOn(header)
}
