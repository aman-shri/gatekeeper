package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestJWTValidator_Validation(t *testing.T) {
	secret := "super-secure-production-secret-key-32-bytes!"
	issuer := "gatekeeper-auth"
	audience := "gatekeeper-api"

	validator := NewJWTValidator(secret, issuer, audience)

	// 1. Valid token generation and validation
	tokenString, err := validator.GenerateToken(Claims{
		TenantID: "tenant-acme",
		UserID:   "usr-john",
		Email:    "john@acme.corp",
		Tier:     "enterprise",
		Roles:    []string{"admin", "read"},
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "usr-john",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("failed to generate valid token: %v", err)
	}

	id, err := validator.Validate(tokenString)
	if err != nil {
		t.Fatalf("expected valid token to pass validation, got: %v", err)
	}
	if id.TenantID != "tenant-acme" || id.UserID != "usr-john" || id.Tier != "enterprise" {
		t.Errorf("unexpected identity extracted from claims: %+v", id)
	}
	if !id.HasRole("admin") {
		t.Errorf("expected role 'admin' on identity")
	}

	// 2. Expired token rejection
	expiredToken, err := validator.GenerateToken(Claims{
		TenantID: "tenant-expired",
		UserID:   "usr-expired",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)), // Expired 1 hour ago
		},
	})
	if err != nil {
		t.Fatalf("failed to generate expired token: %v", err)
	}

	_, err = validator.Validate(expiredToken)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired for expired token, got: %v", err)
	}

	// 3. Invalid signature (tampered token or different secret)
	wrongSecretValidator := NewJWTValidator("completely-different-signing-secret!", issuer, audience)
	tamperedToken, err := wrongSecretValidator.GenerateToken(Claims{
		TenantID: "tenant-tampered",
		UserID:   "usr-tampered",
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = validator.Validate(tamperedToken)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature for token signed with different key, got: %v", err)
	}

	// 4. Invalid Issuer rejection
	wrongIssuerToken, err := validator.GenerateToken(Claims{
		TenantID: "tenant-test",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "unauthorized-foreign-auth-service",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	_, err = validator.Validate(wrongIssuerToken)
	if !errors.Is(err, ErrInvalidIssuer) {
		t.Errorf("expected ErrInvalidIssuer, got: %v", err)
	}

	// 5. Empty token rejection
	_, err = validator.Validate("")
	if !errors.Is(err, ErrMissingToken) {
		t.Errorf("expected ErrMissingToken for empty input, got: %v", err)
	}
}
