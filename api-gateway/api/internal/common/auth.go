package common

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Role describes the authorization level associated with a request.
type Role string

const (
	RoleTrainer    Role = "trainer"
	RoleAggregator Role = "aggregator"
	RoleAdmin      Role = "admin"
)

// AuthContext contains the caller identity resolved from the JWT.
type AuthContext struct {
	Subject string
	NodeID  string
	State   string
	Role    Role
	Token   string
	Claims  *JWTClaims
	Header  *TokenHeader
}

// Authenticator validates and parses incoming JWT bearer tokens.
type Authenticator struct {
	secret []byte
}

// NewAuthenticator constructs an Authenticator instance.
func NewAuthenticator(secret string) (*Authenticator, error) {
	if secret == "" {
		return nil, errors.New("auth secret must be configured")
	}
	return &Authenticator{secret: []byte(secret)}, nil
}

// TokenHeader describes the JWT header fields the gateway cares about.
type TokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	KID string `json:"kid,omitempty"`
}

// JWTClaims captures the subset of claims required by the gateway.
type JWTClaims struct {
	Subject string      `json:"sub"`
	State   string      `json:"state"`
	Role    string      `json:"role"`
	Expiry  json.Number `json:"exp"`
	Issued  json.Number `json:"iat,omitempty"`
}

// KeySpec instructs the authenticator how to verify a token signature.
type KeySpec struct {
	Algorithm string
	Secret    []byte
	PublicKey []byte
}

// KeyFunc resolves the verification key for the token being processed.
type KeyFunc func(header *TokenHeader, claims *JWTClaims) (*KeySpec, error)

// RequireAuth wraps an HTTP handler with JWT authentication and optional role checks.
func (a *Authenticator) RequireAuth(next http.Handler, allowedRoles ...Role) http.Handler {
	return a.RequireAuthWithKeyFunc(nil, next, allowedRoles...)
}

// RequireAuthWithKeyFunc allows callers to override the verification key on a per-token basis.
func (a *Authenticator) RequireAuthWithKeyFunc(keyFunc KeyFunc, next http.Handler, allowedRoles ...Role) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, err := a.authenticateRequest(r, keyFunc)
		if err != nil {
			WriteErrorWithCode(w, http.StatusUnauthorized, ErrInvalidCredentials)
			return
		}
		if len(allowedRoles) > 0 && !authCtx.Role.Allowed(allowedRoles...) {
			WriteErrorWithCode(w, http.StatusForbidden, fmt.Errorf("role %s is not permitted", authCtx.Role))
			return
		}
		ctx := WithAuthContext(r.Context(), authCtx)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) authenticateRequest(r *http.Request, keyFunc KeyFunc) (*AuthContext, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return nil, errors.New("missing Authorization header")
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("authorization header must be in the format Bearer <token>")
	}
	return a.parseToken(parts[1], keyFunc)
}

func (a *Authenticator) parseToken(tokenString string, keyFunc KeyFunc) (*AuthContext, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("token must contain header, payload, and signature")
	}
	headerSegment, payloadSegment, signatureSegment := parts[0], parts[1], parts[2]
	unsigned := fmt.Sprintf("%s.%s", headerSegment, payloadSegment)

	var header TokenHeader
	if err := decodeSegment(headerSegment, &header); err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}
	var claims JWTClaims
	if err := decodeSegment(payloadSegment, &claims); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
	}

	if err := a.verifySignature(unsigned, signatureSegment, &header, &claims, keyFunc); err != nil {
		return nil, err
	}

	if claims.Expiry == "" {
		return nil, errors.New("token missing exp claim")
	}
	exp, err := claims.Expiry.Int64()
	if err != nil {
		return nil, fmt.Errorf("invalid exp claim: %w", err)
	}
	if time.Unix(exp, 0).Before(time.Now()) {
		return nil, errors.New("token has expired")
	}
	state := strings.TrimSpace(claims.State)
	if state == "" {
		return nil, errors.New("token missing state claim")
	}
	role, err := ParseRole(claims.Role)
	if err != nil {
		return nil, err
	}
	subject := strings.TrimSpace(claims.Subject)
	if subject == "" {
		return nil, errors.New("token subject claim is required")
	}
	return &AuthContext{
		Subject: subject,
		NodeID:  subject,
		State:   state,
		Role:    role,
		Token:   tokenString,
		Claims:  &claims,
		Header:  &header,
	}, nil
}

func (a *Authenticator) verifySignature(unsigned, signatureSegment string, header *TokenHeader, claims *JWTClaims, keyFunc KeyFunc) error {
	keySpec, err := a.resolveKey(header, claims, keyFunc)
	if err != nil {
		return err
	}
	switch strings.ToUpper(keySpec.Algorithm) {
	case "HS256":
		return verifyHMACSignature(unsigned, signatureSegment, keySpec.Secret)
	case "EDDSA":
		return verifyEd25519Signature(unsigned, signatureSegment, keySpec.PublicKey)
	default:
		return fmt.Errorf("unsupported signing algorithm %s", keySpec.Algorithm)
	}
}

func (a *Authenticator) resolveKey(header *TokenHeader, claims *JWTClaims, keyFunc KeyFunc) (*KeySpec, error) {
	if keyFunc != nil {
		return keyFunc(header, claims)
	}
	if len(a.secret) == 0 {
		return nil, errors.New("shared-secret authentication is disabled")
	}
	if !strings.EqualFold(header.Alg, "HS256") {
		return nil, fmt.Errorf("expected HS256 token, got %s", header.Alg)
	}
	return &KeySpec{Algorithm: "HS256", Secret: a.secret}, nil
}

func verifyHMACSignature(unsigned, signatureSegment string, secret []byte) error {
	signature, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(unsigned))
	expected := mac.Sum(nil)
	if !hmac.Equal(signature, expected) {
		return errors.New("invalid token signature")
	}
	return nil
}

func verifyEd25519Signature(unsigned, signatureSegment string, publicKey []byte) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key length")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(unsigned), signature) {
		return errors.New("invalid token signature")
	}
	return nil
}

func decodeSegment(segment string, target any) error {
	payload, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(payload, target)
}

// ParseRole converts a string representation into a Role constant.
func ParseRole(value string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(RoleTrainer):
		return RoleTrainer, nil
	case string(RoleAggregator):
		return RoleAggregator, nil
	case string(RoleAdmin):
		return RoleAdmin, nil
	default:
		return "", fmt.Errorf("unknown role %s", value)
	}
}

// Allowed reports whether the current role matches any of the provided roles.
func (r Role) Allowed(roles ...Role) bool {
	if r == "" {
		return false
	}
	for _, role := range roles {
		if r == role {
			return true
		}
	}
	return false
}

type authContextKey struct{}

// WithAuthContext stores the authentication context on the request context.
func WithAuthContext(ctx context.Context, authCtx *AuthContext) context.Context {
	return context.WithValue(ctx, authContextKey{}, authCtx)
}

// AuthContextFrom extracts the auth context from a request context.
func AuthContextFrom(ctx context.Context) (*AuthContext, bool) {
	authCtx, ok := ctx.Value(authContextKey{}).(*AuthContext)
	return authCtx, ok
}
