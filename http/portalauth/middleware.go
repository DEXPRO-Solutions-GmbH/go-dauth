package portalauth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

// Middleware is an OAuth2 middleware for Gin that validates JWT tokens.
//
// You must use NewMiddleware to create a new instance.
//
// To use this middleware, use the GinHandler method.
//
// Requests with invalid or missing tokens will be aborted with a 401 Unauthorized status.
//
// When using this middleware, ContextClaims will return the claims of the JWT token.
type Middleware struct {
	keyfunc jwt.Keyfunc
}

func NewMiddleware(keyfunc jwt.Keyfunc) *Middleware {
	return &Middleware{keyfunc: keyfunc}
}

func (m Middleware) GinHandler(c *gin.Context) {
	// Get token from Authorization header
	tokenStr := c.GetHeader("Authorization")
	if tokenStr == "" || !strings.HasPrefix(tokenStr, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing or invalid"})
		return
	}
	tokenStr = strings.TrimPrefix(tokenStr, "Bearer ")

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, m.keyfunc)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		c.Set(ctxKeyRequestUser, claims)
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
}
