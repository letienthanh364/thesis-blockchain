package registry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nebula/api-gateway/internal/common"
)

// Service coordinates trainer enrollment.
type Service struct {
	cfg      *common.Config
	fabric   *common.FabricClient
	store    *Store
	verifier *VCVerifier
}

// RegisterInput captures the sanitized HTTP payload.
type RegisterInput struct {
	DID        string
	NodeID     string
	VC         json.RawMessage
	PublicKey  string
	JWTSubject string
}

// NewService wires a registry service instance.
func NewService(cfg *common.Config, fabric *common.FabricClient, store *Store, verifier *VCVerifier) *Service {
	return &Service{cfg: cfg, fabric: fabric, store: store, verifier: verifier}
}

// Register validates the VC, calls Fabric, and persists the trainer enrollment.
func (s *Service) Register(ctx context.Context, authCtx *common.AuthContext, input RegisterInput) (*TrainerRecord, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	jwtSub := strings.TrimSpace(input.JWTSubject)
	if jwtSub == "" {
		jwtSub = strings.TrimSpace(authCtx.Subject)
	}
	if jwtSub == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "jwt subject is required")
	}
	did := strings.TrimSpace(input.DID)
	if did == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "did is required")
	}
	nodeID := strings.TrimSpace(input.NodeID)
	if nodeID == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "nodeId is required")
	}
	publicKey := strings.TrimSpace(input.PublicKey)
	if publicKey == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "public_key is required")
	}
	if len(input.VC) == 0 {
		return nil, common.NewStatusError(http.StatusBadRequest, "vc is required")
	}

	verified, err := s.verifier.Verify(input.VC, did)
	if err != nil {
		return nil, common.NewStatusError(http.StatusForbidden, err.Error())
	}
	pubKeyBytes, err := normalizePublicKey(publicKey)
	if err != nil {
		return nil, common.NewStatusError(http.StatusBadRequest, err.Error())
	}
	canonicalPublicKey := base64.StdEncoding.EncodeToString(pubKeyBytes)
	fabricID := buildFabricClientID(nodeID)
	args := []string{"RegisterTrainer", did, nodeID, verified.Hash, canonicalPublicKey}
	if err := s.fabric.InvokeChaincode(s.cfg.DefaultPeer, fabricID, args); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := &TrainerRecord{
		JWTSub:         jwtSub,
		FabricClientID: fabricID,
		DID:            did,
		NodeID:         nodeID,
		VCHash:         verified.Hash,
		PublicKey:      canonicalPublicKey,
		RegisteredAt:   now,
	}
	if err := s.store.Save(record); err != nil {
		return nil, err
	}
	return record, nil
}

func buildFabricClientID(nodeID string) string {
	normalized := strings.ToLower(strings.TrimSpace(nodeID))
	var b strings.Builder
	b.Grow(len(normalized) + 8)
	b.WriteString("")
	for _, r := range normalized {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('-')
		}
	}
	id := b.String()
	id = strings.Trim(id, "-")
	if id == "trainer" {
		return "trainer-default"
	}
	return id
}

func normalizePublicKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("public key is required")
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key must be %d bytes (base64)", ed25519.PublicKeySize)
		}
		return decoded, nil
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("public key must be base64 or hex: %w", err)
	}
	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must be %d bytes (hex)", ed25519.PublicKeySize)
	}
	return decoded, nil
}
