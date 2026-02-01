package models

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nebula/api-gateway/internal/common"
	"github.com/nebula/api-gateway/internal/registry"
)

const defaultPageSize = 10

// Service coordinates Fabric interactions for scoped model references.
type Service struct {
	cfg       *common.Config
	fabric    *common.FabricClient
	store     *registry.Store
	layers    map[string]*Layer
	layerList []*Layer
	pageSize  int
}

// Layer describes a logical scope that model references can belong to.
type Layer struct {
	Name       string
	Slug       string
	ScopeField string
	ScopeLabel string
}

// NewService constructs a Service seeded with the initial layer definitions.
func NewService(cfg *common.Config, fabric *common.FabricClient, store *registry.Store) *Service {
	layers := []*Layer{
		{Name: "Cluster", Slug: "cluster", ScopeField: "cluster_id", ScopeLabel: "cluster"},
		{Name: "State", Slug: "state", ScopeField: "state_id", ScopeLabel: "state"},
		{Name: "Nation", Slug: "nation", ScopeField: "nation_id", ScopeLabel: "nation"},
	}
	index := make(map[string]*Layer, len(layers))
	for _, layer := range layers {
		if layer == nil || layer.Slug == "" {
			continue
		}
		index[layer.Slug] = layer
	}
	return &Service{
		cfg:       cfg,
		fabric:    fabric,
		store:     store,
		layers:    index,
		layerList: layers,
		pageSize:  defaultPageSize,
	}
}

// Layers exposes the configured layer definitions in registration order.
func (s *Service) Layers() []*Layer {
	return s.layerList
}

// Commit registers a model reference scoped to the provided layer.
func (s *Service) Commit(ctx context.Context, authCtx *common.AuthContext, layerSlug, scopeID string, round int, payload json.RawMessage) (*CommitResult, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	layer, err := s.layerBySlug(layerSlug)
	if err != nil {
		return nil, err
	}
	scope := strings.TrimSpace(scopeID)
	if scope == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, layer.ScopeLabel+" identifier is required")
	}
	if len(payload) == 0 {
		return nil, common.NewStatusError(http.StatusBadRequest, "payload is required")
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	dataID := common.GeneratePrefixedID("model")
	roundArg := ""
	if round > 0 {
		roundArg = strconv.Itoa(round)
	}
	args := []string{"CommitModelWithRound", dataID, layer.Slug, scope, roundArg, string(payload)}
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	if err := s.fabric.InvokeChaincode(peerName, enrolment.FabricClientID, args); err != nil {
		return nil, err
	}
	return &CommitResult{
		DataID:      dataID,
		Layer:       layer.Slug,
		ScopeID:     scope,
		NodeID:      enrolment.NodeID,
		VCHash:      enrolment.VCHash,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Retrieve fetches a specific model reference by identifier.
func (s *Service) Retrieve(ctx context.Context, authCtx *common.AuthContext, dataID string) (*ModelRecord, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	dataID = strings.TrimSpace(dataID)
	if dataID == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "data identifier is required")
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	args := []string{"ReadModel", dataID}
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	raw, err := s.fabric.QueryChaincode(peerName, enrolment.FabricClientID, args)
	if err != nil {
		return nil, err
	}
	var ledger ledgerModelRecord
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	return ledger.toModelRecord(), nil
}

// LookupByScopeRound fetches a model reference by scope identifier and round.
func (s *Service) LookupByScopeRound(ctx context.Context, authCtx *common.AuthContext, layerSlug, scopeID string, round int) (*ModelRecord, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	if round < 1 {
		return nil, common.NewStatusError(http.StatusBadRequest, "round must be >= 1")
	}
	layer, err := s.layerBySlug(layerSlug)
	if err != nil {
		return nil, err
	}
	scope := strings.TrimSpace(scopeID)
	if scope == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, layer.ScopeLabel+" identifier is required")
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	args := []string{"ReadModelByScopeRound", layer.Slug, scope, strconv.Itoa(round)}
	raw, err := s.fabric.QueryChaincode(peerName, enrolment.FabricClientID, args)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "model not found") {
			return nil, common.NewStatusError(http.StatusNotFound, fmt.Sprintf("no model provided for %s %s round %d", layer.ScopeLabel, scope, round))
		}
		return nil, err
	}
	var ledger ledgerModelRecord
	if err := json.Unmarshal(raw, &ledger); err != nil {
		return nil, err
	}
	return ledger.toModelRecord(), nil
}

// List returns a paginated collection of model references filtered by scope.
func (s *Service) List(ctx context.Context, authCtx *common.AuthContext, layerSlug, scopeID string, page int) (*ListResult, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	if page < 1 {
		return nil, common.NewStatusError(http.StatusBadRequest, "page must be >= 1")
	}
	layer, err := s.layerBySlug(layerSlug)
	if err != nil {
		return nil, err
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	scope := strings.TrimSpace(scopeID)
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	args := []string{
		"ListModels",
		layer.Slug,
		scope,
		strconv.Itoa(page),
		strconv.Itoa(s.pageSize),
	}
	raw, err := s.fabric.QueryChaincode(peerName, enrolment.FabricClientID, args)
	if err != nil {
		return nil, err
	}
	var ledgerPage ledgerModelList
	if err := json.Unmarshal(raw, &ledgerPage); err != nil {
		return nil, err
	}
	return ledgerPage.toListResult(), nil
}

// Latest returns the most recent model reference for the given layer/scope filter.
func (s *Service) Latest(ctx context.Context, authCtx *common.AuthContext, layerSlug, scopeID string) (*ModelRecord, error) {
	if authCtx == nil {
		return nil, common.NewStatusError(http.StatusUnauthorized, "authentication context missing")
	}
	layer, err := s.layerBySlug(layerSlug)
	if err != nil {
		return nil, err
	}
	enrolment, ok := s.store.FindByJWTSub(authCtx.Subject)
	if !ok {
		return nil, common.NewStatusError(http.StatusForbidden, "trainer not registered")
	}
	peerName := s.fabric.SelectPeer()
	if peerName == "" {
		return nil, common.NewStatusError(http.StatusInternalServerError, "no fabric peers configured")
	}
	scope := strings.TrimSpace(scopeID)
	args := []string{
		"ReadLatestModel",
		layer.Slug,
		scope,
	}
	raw, err := s.fabric.QueryChaincode(peerName, enrolment.FabricClientID, args)
	if err != nil {
		lowerErr := strings.ToLower(err.Error())
		if strings.Contains(lowerErr, "no model found") || strings.Contains(lowerErr, "no models found") {
			if scope != "" {
				return nil, common.NewStatusError(http.StatusNotFound, fmt.Sprintf("no model found for %s %s", layer.ScopeLabel, scope))
			}
			return nil, common.NewStatusError(http.StatusNotFound, fmt.Sprintf("no models found for %s layer", layer.ScopeLabel))
		}
		return nil, err
	}
	var ledgerRecord ledgerModelRecord
	if err := json.Unmarshal(raw, &ledgerRecord); err != nil {
		return nil, err
	}
	return ledgerRecord.toModelRecord(), nil
}

func (s *Service) layerBySlug(slug string) (*Layer, error) {
	key := strings.ToLower(strings.TrimSpace(slug))
	if key == "" {
		return nil, common.NewStatusError(http.StatusBadRequest, "layer is required")
	}
	layer, ok := s.layers[key]
	if !ok {
		return nil, common.NewStatusError(http.StatusNotFound, "layer "+key+" is not supported")
	}
	return layer, nil
}

// CommitResult is returned after successfully recording a model reference.
type CommitResult struct {
	DataID      string `json:"data_id"`
	Layer       string `json:"layer"`
	ScopeID     string `json:"scope_id"`
	NodeID      string `json:"node_id"`
	VCHash      string `json:"vc_hash"`
	SubmittedAt string `json:"submitted_at"`
}

// ModelRecord represents a model reference on-chain.
type ModelRecord struct {
	DataID      string          `json:"data_id"`
	Layer       string          `json:"layer"`
	ScopeID     string          `json:"scope_id"`
	Round       int             `json:"round,omitempty"`
	Owner       string          `json:"owner"`
	Payload     json.RawMessage `json:"payload"`
	SubmittedAt string          `json:"submitted_at"`
}

// ListResult represents one page of model references.
type ListResult struct {
	Items   []*ModelRecord `json:"items"`
	Page    int            `json:"page"`
	PerPage int            `json:"per_page"`
	Total   int            `json:"total"`
	HasMore bool           `json:"has_more"`
}

type ledgerModelRecord struct {
	ID          string          `json:"id"`
	Layer       string          `json:"layer"`
	ScopeID     string          `json:"scope_id"`
	Round       int             `json:"round,omitempty"`
	Owner       string          `json:"owner"`
	Payload     json.RawMessage `json:"payload"`
	SubmittedAt string          `json:"submitted_at"`
}

func (l *ledgerModelRecord) toModelRecord() *ModelRecord {
	if l == nil {
		return nil
	}
	return &ModelRecord{
		DataID:      l.ID,
		Layer:       l.Layer,
		ScopeID:     l.ScopeID,
		Round:       l.Round,
		Owner:       l.Owner,
		Payload:     l.Payload,
		SubmittedAt: l.SubmittedAt,
	}
}

type ledgerModelList struct {
	Items   []*ledgerModelRecord `json:"items"`
	Page    int                  `json:"page"`
	PerPage int                  `json:"per_page"`
	Total   int                  `json:"total"`
	HasMore bool                 `json:"has_more"`
}

func (l *ledgerModelList) toListResult() *ListResult {
	result := &ListResult{
		Page:    l.Page,
		PerPage: l.PerPage,
		Total:   l.Total,
		HasMore: l.HasMore,
	}
	if len(l.Items) == 0 {
		return result
	}
	items := make([]*ModelRecord, 0, len(l.Items))
	for _, ledgerRecord := range l.Items {
		if ledgerRecord == nil {
			continue
		}
		items = append(items, ledgerRecord.toModelRecord())
	}
	result.Items = items
	return result
}
