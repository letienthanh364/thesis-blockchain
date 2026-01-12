package whitelist

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/nebula/api-gateway/internal/common"
)

const defaultPageSize = 50

// Service exposes helper methods to fetch the Fabric whitelist.
type Service struct {
	cfg    *common.Config
	fabric *common.FabricClient
}

// Entry describes a trainer record.
type Entry struct {
	JWTSub       string `json:"jwt_sub"`
	DID          string `json:"did"`
	NodeID       string `json:"node_id"`
	VCHash       string `json:"vc_hash"`
	PublicKey    string `json:"public_key"`
	RegisteredAt string `json:"registered_at"`
}

// ListResult represents a page of whitelist entries.
type ListResult struct {
	Items   []*Entry `json:"items"`
	Page    int      `json:"page"`
	PerPage int      `json:"per_page"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
}

// NewService constructs a whitelist service instance.
func NewService(cfg *common.Config, fabric *common.FabricClient) *Service {
	return &Service{cfg: cfg, fabric: fabric}
}

// List returns whitelist entries from the Fabric ledger.
func (s *Service) List(ctx context.Context, page, perPage int) (*ListResult, error) {
	if page < 1 {
		return nil, common.NewStatusError(http.StatusBadRequest, "page must be >= 1")
	}
	if perPage < 1 {
		perPage = defaultPageSize
	}
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	args := []string{
		"ListWhitelist",
		strconv.Itoa(page),
		strconv.Itoa(perPage),
	}
	raw, err := s.fabric.QueryChaincode(peerName, s.cfg.AdminIdentity, args)
	if err != nil {
		return nil, err
	}
	var ledgerPage ledgerList
	if err := json.Unmarshal(raw, &ledgerPage); err != nil {
		return nil, err
	}
	return ledgerPage.toResult(), nil
}

type ledgerEntry struct {
	JWTSub     string `json:"jwt_sub"`
	DID        string `json:"did"`
	NodeID     string `json:"node_id"`
	VCHash     string `json:"vc_hash"`
	PublicKey  string `json:"public_key"`
	Registered string `json:"registered_at"`
}

type ledgerList struct {
	Items   []*ledgerEntry `json:"items"`
	Page    int            `json:"page"`
	PerPage int            `json:"per_page"`
	Total   int            `json:"total"`
	HasMore bool           `json:"has_more"`
}

func (l *ledgerList) toResult() *ListResult {
	result := &ListResult{
		Page:    l.Page,
		PerPage: l.PerPage,
		Total:   l.Total,
		HasMore: l.HasMore,
	}
	if len(l.Items) == 0 {
		return result
	}
	items := make([]*Entry, 0, len(l.Items))
	for _, entry := range l.Items {
		if entry == nil {
			continue
		}
		items = append(items, &Entry{
			JWTSub:       entry.JWTSub,
			DID:          entry.DID,
			NodeID:       entry.NodeID,
			VCHash:       entry.VCHash,
			PublicKey:    entry.PublicKey,
			RegisteredAt: entry.Registered,
		})
	}
	result.Items = items
	return result
}
