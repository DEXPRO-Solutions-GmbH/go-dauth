package authn

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// MockJwtMiddleware returns a middleware which adds a mocked Jwt to the request's context.
// You should only use this during development or during debugging if you can't / won't setup proper authentication via Keycloak / similar.
func MockJwtMiddleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := mockToken()
		SetCtxJwtGin(ctx, token)
		ctx.Next()
	}
}

func mockToken() *Jwt {
	claims := mockClaims()

	return &Jwt{
		TokenStr: "",
		Token: &jwt.Token{
			Raw:       "",
			Method:    nil,
			Header:    nil,
			Claims:    claims,
			Signature: "",
			Valid:     true,
		},
		Claims: claims,
	}
}

func mockClaims() *Claims {
	return &Claims{
		RegisteredClaims:  jwt.RegisteredClaims{},
		Scope:             "",
		TenantId:          uuid.Nil,
		TenantName:        "Nil Tenant (DEV)",
		Email:             "nil@dexpro.de",
		Name:              "Nil User (DEV)",
		ResourceAccess:    nil,
		RealmAccess:       nil,
		ClientId:          "",
		ClientHost:        "",
		ClientAddress:     "",
		PreferredUsername: "",
	}
}

type mockExtractor struct {
	token string
	err   error
}

func newMockExtractor() *mockExtractor {
	return &mockExtractor{}
}

func (e *mockExtractor) ExtractRequestToken(r *http.Request) (string, error) {
	return e.token, e.err
}

type mockParser struct {
	token  *jwt.Token
	claims *Claims
	err    error
}

func (m *mockParser) ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	return m.token, m.claims, m.err
}

func newMockParser() *mockParser {
	return &mockParser{}
}
