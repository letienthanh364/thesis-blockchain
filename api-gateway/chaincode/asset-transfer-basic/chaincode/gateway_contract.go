package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// GatewayContract provides the Fabric interface used by the API gateway.
type GatewayContract struct {
	contractapi.Contract
}

// Trainer represents an authorized training node.
type Trainer struct {
	ClientID   string `json:"client_id"`
	DID        string `json:"did"`
	NodeID     string `json:"node_id"`
	VCHash     string `json:"vc_hash"`
	PublicKey  string `json:"public_key"`
	Status     string `json:"status"`
	Registered string `json:"registered_at"`
}

// WhitelistEntry captures the trainer whitelist state.
type WhitelistEntry struct {
	JWTSub     string `json:"jwt_sub"`
	DID        string `json:"did"`
	NodeID     string `json:"node_id"`
	VCHash     string `json:"vc_hash"`
	PublicKey  string `json:"public_key"`
	Registered string `json:"registered_at"`
}

// DataRecord describes committed payloads.
type DataRecord struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Payload     string `json:"payload"`
	SubmittedAt string `json:"submitted_at"`
}

// ModelRecord describes a scoped model reference.
type ModelRecord struct {
	ID          string `json:"id"`
	Layer       string `json:"layer"`
	ScopeID     string `json:"scope_id"`
	Owner       string `json:"owner"`
	Payload     string `json:"payload"`
	SubmittedAt string `json:"submitted_at"`
}

// ModelListPage represents a single page of model references.
type ModelListPage struct {
	Items   []*ModelRecord `json:"items"`
	Page    int            `json:"page"`
	PerPage int            `json:"per_page"`
	Total   int            `json:"total"`
	HasMore bool           `json:"has_more"`
}

// WhitelistListPage returns paginated whitelist results.
type WhitelistListPage struct {
	Items   []*WhitelistEntry `json:"items"`
	Page    int               `json:"page"`
	PerPage int               `json:"per_page"`
	Total   int               `json:"total"`
	HasMore bool              `json:"has_more"`
}

const (
	trainerPrefix   = "trainer:"
	dataPrefix      = "data:"
	modelPrefix     = "model:"
	whitelistPrefix = "whitelist:"
)

// InitLedger is present for compatibility with the bootstrap script.
func (c *GatewayContract) InitLedger(contractapi.TransactionContextInterface) error {
	return nil
}

// RegisterTrainer stores the trainer metadata keyed to the invoker identity.
func (c *GatewayContract) RegisterTrainer(ctx contractapi.TransactionContextInterface, did, nodeID, vcHash, publicKey string) error {
	if strings.TrimSpace(did) == "" {
		return errors.New("did is required")
	}
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("nodeId is required")
	}
	if strings.TrimSpace(vcHash) == "" {
		return errors.New("vcHash is required")
	}
	if strings.TrimSpace(publicKey) == "" {
		return errors.New("publicKey is required")
	}
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to resolve client identity: %w", err)
	}
	trainer := &Trainer{
		ClientID:   clientID,
		DID:        did,
		NodeID:     nodeID,
		VCHash:     vcHash,
		PublicKey:  publicKey,
		Status:     "AUTHORIZED",
		Registered: time.Now().UTC().Format(time.RFC3339),
	}
	payload, err := json.Marshal(trainer)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(trainerKey(clientID), payload)
}

// IsTrainerAuthorized reports whether the invoker identity is registered and active.
func (c *GatewayContract) IsTrainerAuthorized(ctx contractapi.TransactionContextInterface) (bool, error) {
	_, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		if errors.Is(err, errTrainerUnauthorized) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CommitData stores an arbitrary payload (as a string) on-chain.
func (c *GatewayContract) CommitData(ctx contractapi.TransactionContextInterface, dataID, payload string) (*DataRecord, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataID) == "" {
		return nil, errors.New("data identifier is required")
	}
	record := &DataRecord{
		ID:          dataID,
		Owner:       trainer.NodeID,
		Payload:     payload,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(dataKey(dataID), bytes); err != nil {
		return nil, err
	}
	return record, nil
}

// ReadData returns a payload if the caller is authorized to access it.
func (c *GatewayContract) ReadData(ctx contractapi.TransactionContextInterface, dataID string) (*DataRecord, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataID) == "" {
		return nil, errors.New("data identifier is required")
	}
	payload, err := ctx.GetStub().GetState(dataKey(dataID))
	if err != nil {
		return nil, fmt.Errorf("failed to read record: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("record %s not found", dataID)
	}
	var record DataRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, err
	}
	// Each authorized trainer is allowed to read any committed record.
	return &record, nil
}

// CommitModel stores a model reference scoped to a layer/scope identifier.
func (c *GatewayContract) CommitModel(ctx contractapi.TransactionContextInterface, dataID, layer, scopeID, payload string) (*ModelRecord, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	id := strings.TrimSpace(dataID)
	if id == "" {
		return nil, errors.New("data identifier is required")
	}
	normalizedLayer := strings.ToLower(strings.TrimSpace(layer))
	if normalizedLayer == "" {
		return nil, errors.New("layer is required")
	}
	scope := strings.TrimSpace(scopeID)
	if scope == "" {
		return nil, errors.New("scope identifier is required")
	}
	record := &ModelRecord{
		ID:          id,
		Layer:       normalizedLayer,
		ScopeID:     scope,
		Owner:       trainer.NodeID,
		Payload:     payload,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(modelKey(id), bytes); err != nil {
		return nil, err
	}
	return record, nil
}

// ReadModel returns a previously committed model reference.
func (c *GatewayContract) ReadModel(ctx contractapi.TransactionContextInterface, dataID string) (*ModelRecord, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataID) == "" {
		return nil, errors.New("data identifier is required")
	}
	payload, err := ctx.GetStub().GetState(modelKey(dataID))
	if err != nil {
		return nil, fmt.Errorf("failed to read model record: %w", err)
	}
	if len(payload) == 0 {
		return nil, fmt.Errorf("model %s not found", dataID)
	}
	var record ModelRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// ListModels returns a page of model references filtered by layer/scope.
func (c *GatewayContract) ListModels(ctx contractapi.TransactionContextInterface, layer, scopeID, pageArg, perPageArg string) (*ModelListPage, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	layerFilter := strings.ToLower(strings.TrimSpace(layer))
	if layerFilter == "" {
		return nil, errors.New("layer is required")
	}
	page := 1
	if strings.TrimSpace(pageArg) != "" {
		parsed, err := strconv.Atoi(pageArg)
		if err != nil {
			return nil, fmt.Errorf("invalid page parameter: %w", err)
		}
		if parsed < 1 {
			return nil, errors.New("page must be >= 1")
		}
		page = parsed
	}
	perPage := 10
	if strings.TrimSpace(perPageArg) != "" {
		parsed, err := strconv.Atoi(perPageArg)
		if err != nil {
			return nil, fmt.Errorf("invalid perPage parameter: %w", err)
		}
		if parsed < 1 {
			return nil, errors.New("perPage must be >= 1")
		}
		perPage = parsed
	}
	scopeFilter := strings.TrimSpace(scopeID)
	startIndex := (page - 1) * perPage
	items := make([]*ModelRecord, 0, perPage)

	iter, err := ctx.GetStub().GetStateByRange(modelPrefix, modelPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	defer iter.Close()

	matched := 0
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to advance iterator: %w", err)
		}
		var record ModelRecord
		if err := json.Unmarshal(kv.Value, &record); err != nil {
			return nil, err
		}
		if record.ID == "" {
			continue
		}
		if !strings.EqualFold(record.Layer, layerFilter) {
			continue
		}
		if scopeFilter != "" && !strings.EqualFold(record.ScopeID, scopeFilter) {
			continue
		}
		matched++
		if matched <= startIndex {
			continue
		}
		if len(items) >= perPage {
			continue
		}
		copy := record
		items = append(items, &copy)
	}

	hasMore := matched > startIndex+len(items)
	return &ModelListPage{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   matched,
		HasMore: hasMore,
	}, nil
}

// RecordWhitelistEntry upserts whitelist metadata keyed by JWT subject.
func (c *GatewayContract) RecordWhitelistEntry(ctx contractapi.TransactionContextInterface, jwtSub, did, nodeID, vcHash, publicKey, registered string) error {
	jwtSub = strings.TrimSpace(jwtSub)
	if jwtSub == "" {
		return errors.New("jwtSub is required")
	}
	if strings.TrimSpace(did) == "" {
		return errors.New("did is required")
	}
	if strings.TrimSpace(nodeID) == "" {
		return errors.New("nodeId is required")
	}
	if strings.TrimSpace(vcHash) == "" {
		return errors.New("vcHash is required")
	}
	if strings.TrimSpace(publicKey) == "" {
		return errors.New("publicKey is required")
	}
	registeredAt := strings.TrimSpace(registered)
	if registeredAt == "" {
		registeredAt = time.Now().UTC().Format(time.RFC3339)
	}
	entry := &WhitelistEntry{
		JWTSub:     strings.ToLower(jwtSub),
		DID:        did,
		NodeID:     nodeID,
		VCHash:     vcHash,
		PublicKey:  publicKey,
		Registered: registeredAt,
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(whitelistKey(entry.JWTSub), payload)
}

// ListWhitelist returns trainers recorded on-chain.
func (c *GatewayContract) ListWhitelist(ctx contractapi.TransactionContextInterface, pageArg, perPageArg string) (*WhitelistListPage, error) {
	page := 1
	if strings.TrimSpace(pageArg) != "" {
		value, err := strconv.Atoi(pageArg)
		if err != nil {
			return nil, fmt.Errorf("invalid page parameter: %w", err)
		}
		if value < 1 {
			return nil, errors.New("page must be >= 1")
		}
		page = value
	}
	perPage := 50
	if strings.TrimSpace(perPageArg) != "" {
		value, err := strconv.Atoi(perPageArg)
		if err != nil {
			return nil, fmt.Errorf("invalid perPage parameter: %w", err)
		}
		if value < 1 {
			return nil, errors.New("perPage must be >= 1")
		}
		perPage = value
	}
	iter, err := ctx.GetStub().GetStateByRange(whitelistPrefix, whitelistPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to list whitelist: %w", err)
	}
	defer iter.Close()

	start := (page - 1) * perPage
	total := 0
	items := make([]*WhitelistEntry, 0, perPage)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to advance iterator: %w", err)
		}
		var entry WhitelistEntry
		if err := json.Unmarshal(kv.Value, &entry); err != nil {
			return nil, err
		}
		if entry.JWTSub == "" {
			continue
		}
		total++
		if total <= start {
			continue
		}
		if len(items) >= perPage {
			continue
		}
		copy := entry
		items = append(items, &copy)
	}
	hasMore := total > start+len(items)
	return &WhitelistListPage{
		Items:   items,
		Page:    page,
		PerPage: perPage,
		Total:   total,
		HasMore: hasMore,
	}, nil
}

var errTrainerUnauthorized = errors.New("trainer not authorized")

func (c *GatewayContract) requireAuthorizedTrainer(ctx contractapi.TransactionContextInterface) (*Trainer, error) {
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve client identity: %w", err)
	}
	payload, err := ctx.GetStub().GetState(trainerKey(clientID))
	if err != nil {
		return nil, fmt.Errorf("failed to read trainer record: %w", err)
	}
	if len(payload) == 0 {
		return nil, errTrainerUnauthorized
	}
	var trainer Trainer
	if err := json.Unmarshal(payload, &trainer); err != nil {
		return nil, err
	}
	if !strings.EqualFold(trainer.Status, "AUTHORIZED") {
		return nil, errTrainerUnauthorized
	}
	return &trainer, nil
}

func trainerKey(clientID string) string {
	return trainerPrefix + clientID
}

func dataKey(id string) string {
	return dataPrefix + id
}

func modelKey(id string) string {
	return modelPrefix + id
}

func whitelistKey(jwtSub string) string {
	return whitelistPrefix + strings.ToLower(strings.TrimSpace(jwtSub))
}
