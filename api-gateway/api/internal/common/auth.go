package common

import (
	"context"
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

// RequireAuth wraps an HTTP handler with JWT authentication and optional role checks.
func (a *Authenticator) RequireAuth(next http.Handler, allowedRoles ...Role) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authCtx, err := a.authenticateRequest(r)
		if err != nil {
			WriteErrorWithCode(w, http.StatusUnauthorized, err)
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

func (a *Authenticator) authenticateRequest(r *http.Request) (*AuthContext, error) {
	raw := strings.TrimSpace(r.Header.Get("Authorization"))
	if raw == "" {
		return nil, errors.New("missing Authorization header")
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, errors.New("authorization header must be in the format Bearer <token>")
	}
	return a.parseToken(parts[1])
}

func (a *Authenticator) parseToken(tokenString string) (*AuthContext, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("token must contain header, payload, and signature")
	}
	headerSegment, payloadSegment, signatureSegment := parts[0], parts[1], parts[2]
	unsigned := fmt.Sprintf("%s.%s", headerSegment, payloadSegment)
	if err := a.verifySignature(unsigned, signatureSegment); err != nil {
		return nil, err
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := decodeSegment(headerSegment, &header); err != nil {
		return nil, fmt.Errorf("invalid token header: %w", err)
	}
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported signing algorithm %s", header.Alg)
	}
	var claims struct {
		Subject string      `json:"sub"`
		State   string      `json:"state"`
		Role    string      `json:"role"`
		Expiry  json.Number `json:"exp"`
		Expires int64       `json:"-"`
	}
	if err := decodeSegment(payloadSegment, &claims); err != nil {
		return nil, fmt.Errorf("invalid token payload: %w", err)
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
	}, nil
}

func (a *Authenticator) verifySignature(unsigned, signatureSegment string) error {
	signature, err := base64.RawURLEncoding.DecodeString(signatureSegment)
	if err != nil {
		return fmt.Errorf("invalid token signature: %w", err)
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(unsigned))
	expected := mac.Sum(nil)
	if !hmac.Equal(signature, expected) {
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
