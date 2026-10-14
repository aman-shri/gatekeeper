package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMissingToken       = errors.New("authorization token is missing")
	ErrInvalidTokenFormat = errors.New("invalid authorization token format")
	ErrTokenExpired       = errors.New("authorization token has expired")
	ErrTokenNotYetValid   = errors.New("authorization token is not yet valid")
	ErrInvalidSignature   = errors.New("token signature is invalid")
	ErrInvalidIssuer      = errors.New("token issuer is invalid")
	ErrInvalidAudience    = errors.New("token audience is invalid")
	ErrUnexpectedAlg      = errors.New("unexpected signing algorithm")
)

// Claims defines custom Gatekeeper claims along with standard RFC 7519 registered claims.
type Claims struct {
	TenantID          string   `json:"tenant_id,omitempty"`
	UserID            string   `json:"user_id,omitempty"`
	Email             string   `json:"email,omitempty"`
	Tier              string   `json:"tier,omitempty"`
	Roles             []string `json:"roles,omitempty"`
	RateLimitOverride int      `json:"rate_limit_override,omitempty"`
	jwt.RegisteredClaims
}

// JWTValidator validates and parses JWT tokens using HMAC-SHA256.
type JWTValidator struct {
	secret   []byte
	issuer   string
	audience string
}

// NewJWTValidator constructs a new JWT validator.
func NewJWTValidator(secret, issuer, audience string) *JWTValidator {
	return &JWTValidator{
		secret:   []byte(secret),
		issuer:   issuer,
		audience: audience,
	}
}

// Validate parses, verifies cryptographic signature, and checks standard claims on a token string.
func (v *JWTValidator) Validate(tokenString string) (*Identity, error) {
	if tokenString == "" {
		return nil, ErrMissingToken
	}

	parserOptions := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg(), jwt.SigningMethodHS384.Alg(), jwt.SigningMethodHS512.Alg()}),
	}
	if v.issuer != "" {
		parserOptions = append(parserOptions, jwt.WithIssuer(v.issuer))
	}
	if v.audience != "" {
		parserOptions = append(parserOptions, jwt.WithAudience(v.audience))
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		// Strict check against algorithm confusion attacks
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%w: %v", ErrUnexpectedAlg, t.Header["alg"])
		}
		return v.secret, nil
	}, parserOptions...)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, ErrInvalidSignature
		}
		if errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			return nil, ErrInvalidIssuer
		}
		if errors.Is(err, jwt.ErrTokenInvalidAudience) {
			return nil, ErrInvalidAudience
		}
		return nil, fmt.Errorf("%w: %s", ErrInvalidTokenFormat, err.Error())
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidTokenFormat
	}

	tier := claims.Tier
	if tier == "" {
		tier = "standard"
	}

	userID := claims.UserID
	if userID == "" && claims.Subject != "" {
		userID = claims.Subject
	}
	if userID == "" {
		userID = "anonymous"
	}

	tenantID := claims.TenantID
	if tenantID == "" {
		tenantID = userID
	}

	return &Identity{
		TenantID:          tenantID,
		UserID:            userID,
		Email:             claims.Email,
		Tier:              tier,
		Roles:             claims.Roles,
		AuthType:          "jwt",
		RateLimitOverride: claims.RateLimitOverride,
	}, nil
}

// GenerateToken is a convenience utility to sign a valid JWT token (useful for clients, tests, and CLI).
func (v *JWTValidator) GenerateToken(claims Claims) (string, error) {
	if claims.ExpiresAt == nil {
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(24 * time.Hour))
	}
	if claims.IssuedAt == nil {
		claims.IssuedAt = jwt.NewNumericDate(time.Now())
	}
	if v.issuer != "" && claims.Issuer == "" {
		claims.Issuer = v.issuer
	}
	if v.audience != "" && len(claims.Audience) == 0 {
		claims.Audience = jwt.ClaimStrings{v.audience}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(v.secret)
}
