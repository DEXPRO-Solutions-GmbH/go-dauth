package authn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims_Json(t *testing.T) {
	claims := mockClaims()
	actual, err := json.Marshal(claims)
	require.NoError(t, err)
	expected := `{"email":"nil@dexpro.de", "name":"Nil User (DEV)", "tenant_id":"00000000-0000-0000-0000-000000000000", "tenant_name":"Nil Tenant (DEV)"}`
	assert.JSONEq(t, expected, string(actual))
}

// TestClaims_Valid ensures that the validation of Claims is correct. This test is important
// because it ensures that no invalid Claims are picked up by API handlers.
func TestClaims_Valid(t *testing.T) {
	newValidClaims := func() *Claims {
		return &Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "",
				Subject:   "",
				Audience:  nil,
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
				NotBefore: nil,
				IssuedAt:  jwt.NewNumericDate(time.Now().Add(time.Minute * -1)),
				ID:        "",
			},
			Scope:          "",
			TenantId:       uuid.New(),
			TenantName:     "DEXPRO Solutions GmbH",
			Email:          "terstegen@dexpro.de",
			Name:           "",
			ResourceAccess: nil,
			RealmAccess:    nil,
		}
	}

	t.Run("valid", func(t *testing.T) {
		claims := newValidClaims()
		assert.NoError(t, claims.Valid())
	})

	t.Run("invalid", func(t *testing.T) {
		t.Run("zero value", func(t *testing.T) {
			claims := &Claims{}
			assert.Error(t, claims.Valid())
		})

		t.Run("tenant id", func(t *testing.T) {
			t.Run("missing", func(t *testing.T) {
				claims := newValidClaims()
				claims.TenantId = uuid.Nil
				assert.Error(t, claims.Valid())
			})
		})

		t.Run("tenant name", func(t *testing.T) {
			t.Run("missing", func(t *testing.T) {
				claims := newValidClaims()
				claims.TenantName = ""
				assert.Error(t, claims.Valid())
			})
		})

		t.Run("exp claim", func(t *testing.T) {
			t.Run("missing", func(t *testing.T) {
				claims := newValidClaims()
				claims.ExpiresAt = nil
				assert.Error(t, claims.Valid())
			})

			t.Run("expired", func(t *testing.T) {
				claims := newValidClaims()
				claims.RegisteredClaims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Minute))
				assert.Error(t, claims.Valid())
			})
		})

		t.Run("iat claim", func(t *testing.T) {
			t.Run("missing", func(t *testing.T) {
				claims := newValidClaims()
				claims.IssuedAt = nil
				assert.Error(t, claims.Valid())
			})

			t.Run("in future", func(t *testing.T) {
				claims := newValidClaims()
				claims.RegisteredClaims.IssuedAt = jwt.NewNumericDate(time.Now().Add(1 * time.Minute))
				assert.Error(t, claims.Valid())
			})
		})
	})
}
