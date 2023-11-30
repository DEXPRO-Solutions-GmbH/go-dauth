package authn

import (
	"errors"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

// Claims is a custom type that contains fields for all claims used by DEXPRO services.
type Claims struct {
	jwt.RegisteredClaims

	Scope string `json:"scope,omitempty"`

	// TenantId
	//
	// This claim is set on tokens that are scoped to a tenant, ie a customer / organization consuming some service.
	TenantId   uuid.UUID `json:"tenant_id,omitempty"`
	TenantName string    `json:"tenant_name,omitempty"`

	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`

	// ResourceAccess is set by Keycloak on default clients
	ResourceAccess map[string]map[string][]string `json:"resource_access,omitempty"`

	// RealmAccess is set by Keycloak on default clients
	RealmAccess map[string][]string `json:"realm_access,omitempty"`

	// ClientId is set by Keycloak on client using client credentials grant
	ClientId string `json:"clientId,omitempty"`
	// ClientHost is set by Keycloak on client using client credentials grant
	ClientHost string `json:"clientHost,omitempty"`
	// ClientAddress is set by Keycloak on client using client credentials grant
	ClientAddress string `json:"clientAddress,omitempty"`

	PreferredUsername string `json:"preferred_username,omitempty"`
}

// Valid is the method called by the jwt library when parsing and validating a token.
func (claims Claims) Valid() error {
	if err := RequireExpAndIssuedAtClaims(claims.RegisteredClaims); err != nil {
		return err
	}

	// Default validation
	if err := claims.RegisteredClaims.Valid(); err != nil {
		return err
	}

	// Validate email if present
	if claims.Email != "" {
		// TODO: Validate email - is it a valid email? For now we trust the identity provider.
	}

	// Validate tenant
	if claims.TenantId == uuid.Nil {
		return errors.New("invalid tenant id claim")
	}

	// Tenant name must be set
	if claims.TenantName == "" {
		return errors.New("tenant name may not be empty")
	}

	return nil
}

var (
	errMissingExpClaim = errors.New("missing exp claim")
	errMissingIatClaim = errors.New("missing iat claim")
)

// RequireExpAndIssuedAtClaims checks that the given claims contain exp and iat claims.
//
// You may want to use this because jwt.RegisteredClaims.Valid() does not check for the existence of these claims.
func RequireExpAndIssuedAtClaims(claims jwt.RegisteredClaims) error {
	if claims.ExpiresAt == nil {
		return errMissingExpClaim
	}
	if claims.IssuedAt == nil {
		return errMissingIatClaim
	}
	return nil
}

func (claims *Claims) HasTenantId() bool {
	return claims.TenantId != uuid.Nil
}
