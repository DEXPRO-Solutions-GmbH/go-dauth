package portalauth

import (
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

const ctxKeyRequestUser = "github.com/DEXPRO-Solutions-GmbH/go-dauth/claims"

// Claims is the proprietary claims object for JWT tokens issued by the Portal.
type Claims struct {
	ProjectID      uuid.UUID `json:"project_id"`
	OrganisationID uuid.UUID `json:"organisation_id"`

	jwt.RegisteredClaims
}

func ContextClaims(c *gin.Context) *Claims {
	if claims, ok := c.Value(ctxKeyRequestUser).(*Claims); ok {
		return claims
	}

	return nil
}
