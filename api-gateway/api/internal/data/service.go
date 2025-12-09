package data

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nebula/api-gateway/internal/common"
	"github.com/nebula/api-gateway/internal/registry"
)

// Service handles Fabric transactions for commit/retrieve operations.
type Service struct {
	cfg    *common.Config
	fabric *common.FabricClient
	store  *registry.Store
}

// NewService instantiates a data service.
func NewService(cfg *common.Config, fabric *common.FabricClient, store *registry.Store) *Service {
	return &Service{cfg: cfg, fabric: fabric, store: store}
}

// Commit stores arbitrary payloads on-chain and returns their identifier.
func (s *Service) Commit(ctx context.Context, authCtx *common.AuthContext, payload json.RawMessage) (*CommitResult, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	if len(payload) == 0 {
		return nil, common.NewStatusError(http.StatusBadRequest, "payload is required")
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	dataID := generateDataID()
	args := []string{"CommitData", dataID, string(payload)}
	if err := s.fabric.InvokeChaincode(s.cfg.DefaultPeer, enrolment.FabricClientID, args); err != nil {
		return nil, err
	}
	return &CommitResult{
		DataID:      dataID,
		NodeID:      enrolment.NodeID,
		VCHash:      enrolment.VCHash,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Retrieve loads a payload by identifier and verifies access rights.
func (s *Service) Retrieve(ctx context.Context, authCtx *common.AuthContext, dataID string) (*DataRecord, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	if strings.TrimSpace(dataID) == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "data identifier is required")
	}
	args := []string{"ReadData", dataID}
	raw, err := s.fabric.QueryChaincode(s.cfg.DefaultPeer, enrolment.FabricClientID, args)
	if err != nil {
		return nil, err
	}
	var ledger ledgerRecord
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	if ledger.Owner != "" && !strings.EqualFold(ledger.Owner, enrolment.NodeID) {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not authorized for this record")
	}
	return &DataRecord{
		DataID:      ledger.ID,
		Payload:     ledger.Payload,
		Owner:       ledger.Owner,
		SubmittedAt: ledger.SubmittedAt,
	}, nil
}

func generateDataID() string {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// Fallback to timestamp to keep ID generation moving.
		return fmt.Sprintf("data-%d", time.Now().UnixNano())
	}
	return "data-" + hex.EncodeToString(buf[:])
}

// CommitResult describes the API response for commits.
type CommitResult struct {
	DataID      string `json:"data_id"`
	NodeID      string `json:"node_id"`
	VCHash      string `json:"vc_hash"`
	SubmittedAt string `json:"submitted_at"`
}

// DataRecord describes chaincode records returned to clients.
type DataRecord struct {
	DataID      string          `json:"data_id"`
	Payload     json.RawMessage `json:"payload"`
	Owner       string          `json:"owner"`
	SubmittedAt string          `json:"submitted_at"`
}

type ledgerRecord struct {
	ID          string          `json:"id"`
	Owner       string          `json:"owner"`
	Payload     json.RawMessage `json:"payload"`
	SubmittedAt string          `json:"submitted_at"`
}
