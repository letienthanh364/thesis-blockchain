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
	State      string `json:"state,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
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
	State      string `json:"state,omitempty"`
	Cluster    string `json:"cluster,omitempty"`
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
	Round       int    `json:"round,omitempty"`
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

// ConvergenceRecord captures a convergence payload for a given scope.
type ConvergenceRecord struct {
	Scope       string `json:"scope"`
	StateID     string `json:"state_id"`
	ClusterID   string `json:"cluster_id,omitempty"`
	SourceID    string `json:"source_id"`
	Payload     string `json:"payload"`
	SubmittedAt string `json:"submitted_at"`
}

// ConvergenceSummary declares that a scope is fully converged.
type ConvergenceSummary struct {
	Scope      string `json:"scope"`
	TargetID   string `json:"target_id"`
	DeclaredBy string `json:"declared_by"`
	DeclaredAt string `json:"declared_at"`
	Payload    string `json:"payload"`
}

// StateConvergence aggregates cluster convergence states for a state.
type StateConvergence struct {
	StateID  string                        `json:"state_id"`
	Clusters map[string]*ConvergenceRecord `json:"clusters"`
	Summary  *ConvergenceSummary           `json:"summary,omitempty"`
}

// NationConvergence aggregates state convergence states for the nation.
type NationConvergence struct {
	States  map[string]*ConvergenceRecord `json:"states"`
	Summary *ConvergenceSummary           `json:"summary,omitempty"`
}

const (
	trainerPrefix         = "trainer:"
	dataPrefix            = "data:"
	modelPrefix           = "model:"
	modelScopeRoundPrefix = "model_scope_round:"
	whitelistPrefix       = "whitelist:"
	stateConvPrefix       = "conv:state:"
	nationConvPrefix      = "conv:nation:"
	clusterSuffix         = ":cluster:"
	stateSummarySuffix    = ":summary"
)

// InitLedger is present for compatibility with the bootstrap script.
func (c *GatewayContract) InitLedger(contractapi.TransactionContextInterface) error {
	return nil
}

// RegisterTrainer stores the trainer metadata keyed to the invoker identity.
func (c *GatewayContract) RegisterTrainer(ctx contractapi.TransactionContextInterface, did, nodeID, vcHash, publicKey, state, cluster string) error {
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
	state = strings.TrimSpace(state)
	cluster = strings.TrimSpace(cluster)
	clientID, err := ctx.GetClientIdentity().GetID()
	if err != nil {
		return fmt.Errorf("failed to resolve client identity: %w", err)
	}
	trainer := &Trainer{
		ClientID:   clientID,
		DID:        did,
		NodeID:     nodeID,
		State:      state,
		Cluster:    cluster,
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
	return c.commitModel(ctx, dataID, layer, scopeID, "", payload)
}

// CommitModelWithRound stores a model reference that is tied to a specific round within the scope.
func (c *GatewayContract) CommitModelWithRound(ctx contractapi.TransactionContextInterface, dataID, layer, scopeID, round, payload string) (*ModelRecord, error) {
	return c.commitModel(ctx, dataID, layer, scopeID, round, payload)
}

func (c *GatewayContract) commitModel(ctx contractapi.TransactionContextInterface, dataID, layer, scopeID, roundArg, payload string) (*ModelRecord, error) {
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
	round, err := parseRound(roundArg, false)
	if err != nil {
		return nil, err
	}
	record := &ModelRecord{
		ID:          id,
		Layer:       normalizedLayer,
		ScopeID:     scope,
		Round:       round,
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
	if round > 0 {
		indexKey := modelScopeRoundKey(normalizedLayer, scope, round)
		if err := ctx.GetStub().PutState(indexKey, []byte(record.ID)); err != nil {
			return nil, err
		}
	}
	return record, nil
}

// ReadModel returns a previously committed model reference.
func (c *GatewayContract) ReadModel(ctx contractapi.TransactionContextInterface, dataID string) (*ModelRecord, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	return c.loadModel(ctx, dataID)
}

// ReadModelByScopeRound returns a model reference bound to a specific scope round.
func (c *GatewayContract) ReadModelByScopeRound(ctx contractapi.TransactionContextInterface, layer, scopeID, round string) (*ModelRecord, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	normalizedLayer, err := normalizeIdentifier(layer, "layer")
	if err != nil {
		return nil, err
	}
	scope, err := normalizeIdentifier(scopeID, "scope identifier")
	if err != nil {
		return nil, err
	}
	roundNumber, err := parseRound(round, true)
	if err != nil {
		return nil, err
	}
	indexKey := modelScopeRoundKey(normalizedLayer, scope, roundNumber)
	dataIDBytes, err := ctx.GetStub().GetState(indexKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read scope round index: %w", err)
	}
	if len(dataIDBytes) == 0 {
		return nil, fmt.Errorf("model not found for %s %s round %d", normalizedLayer, scope, roundNumber)
	}
	return c.loadModel(ctx, string(dataIDBytes))
}

func (c *GatewayContract) loadModel(ctx contractapi.TransactionContextInterface, dataID string) (*ModelRecord, error) {
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
	layerFilter, err := normalizeIdentifier(layer, "layer")
	if err != nil {
		return nil, err
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

// ReadLatestModel returns the most recent model reference for a layer/scope combination.
func (c *GatewayContract) ReadLatestModel(ctx contractapi.TransactionContextInterface, layer, scopeID string) (*ModelRecord, error) {
	if _, err := c.requireAuthorizedTrainer(ctx); err != nil {
		return nil, err
	}
	layerFilter, err := normalizeIdentifier(layer, "layer")
	if err != nil {
		return nil, err
	}
	scopeFilter := strings.TrimSpace(scopeID)
	iter, err := ctx.GetStub().GetStateByRange(modelPrefix, modelPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to list models: %w", err)
	}
	defer iter.Close()

	var latest *ModelRecord
	var latestTime time.Time
	var latestTimeValid bool
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to advance iterator: %w", err)
		}
		var record ModelRecord
		if err := json.Unmarshal(kv.Value, &record); err != nil {
			return nil, err
		}
		if record.ID == "" || !strings.EqualFold(record.Layer, layerFilter) {
			continue
		}
		if scopeFilter != "" && !strings.EqualFold(record.ScopeID, scopeFilter) {
			continue
		}
		submittedAt := strings.TrimSpace(record.SubmittedAt)
		recordTime, parseErr := time.Parse(time.RFC3339, submittedAt)
		recordTimeValid := parseErr == nil
		shouldUpdate := false
		switch {
		case latest == nil:
			shouldUpdate = true
		case recordTimeValid && latestTimeValid:
			if recordTime.After(latestTime) || (recordTime.Equal(latestTime) && record.ID > latest.ID) {
				shouldUpdate = true
			}
		case recordTimeValid && !latestTimeValid:
			shouldUpdate = true
		case !recordTimeValid && !latestTimeValid:
			currentSubmitted := strings.TrimSpace(latest.SubmittedAt)
			if submittedAt > currentSubmitted || (submittedAt == currentSubmitted && record.ID > latest.ID) {
				shouldUpdate = true
			}
		}
		if shouldUpdate {
			copyRecord := record
			latest = &copyRecord
			if recordTimeValid {
				latestTime = recordTime
			}
			latestTimeValid = recordTimeValid
		}
	}
	if latest == nil {
		if scopeFilter != "" {
			return nil, fmt.Errorf("no model found for %s %s", layerFilter, scopeFilter)
		}
		return nil, fmt.Errorf("no models found for layer %s", layerFilter)
	}
	return latest, nil
}

// RecordWhitelistEntry upserts whitelist metadata keyed by JWT subject.
func (c *GatewayContract) RecordWhitelistEntry(ctx contractapi.TransactionContextInterface, jwtSub, did, nodeID, state, cluster, vcHash, publicKey, registered string) error {
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
	state = strings.TrimSpace(state)
	cluster = strings.TrimSpace(cluster)
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
		State:      state,
		Cluster:    cluster,
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

// CommitStateClusterConvergence records convergence data for a specific cluster within a state.
func (c *GatewayContract) CommitStateClusterConvergence(ctx contractapi.TransactionContextInterface, stateID, clusterID, payload string) (*ConvergenceRecord, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	stateID, err = normalizeIdentifier(stateID, "stateId")
	if err != nil {
		return nil, err
	}
	clusterID, err = normalizeIdentifier(clusterID, "clusterId")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload) == "" {
		return nil, errors.New("payload is required")
	}
	record := &ConvergenceRecord{
		Scope:       "state",
		StateID:     stateID,
		ClusterID:   clusterID,
		SourceID:    trainer.NodeID,
		Payload:     payload,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(stateClusterKey(stateID, clusterID), bytes); err != nil {
		return nil, err
	}
	return record, nil
}

// CommitNationStateConvergence records convergence data for a state toward the nation scope.
func (c *GatewayContract) CommitNationStateConvergence(ctx contractapi.TransactionContextInterface, stateID, payload string) (*ConvergenceRecord, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	stateID, err = normalizeIdentifier(stateID, "stateId")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(payload) == "" {
		return nil, errors.New("payload is required")
	}
	record := &ConvergenceRecord{
		Scope:       "nation",
		StateID:     stateID,
		SourceID:    trainer.NodeID,
		Payload:     payload,
		SubmittedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(nationStateKey(stateID), bytes); err != nil {
		return nil, err
	}
	return record, nil
}

// DeclareStateConvergence marks an entire state as converged (first declaration wins).
func (c *GatewayContract) DeclareStateConvergence(ctx contractapi.TransactionContextInterface, stateID, payload string) (*ConvergenceSummary, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	stateID, err = normalizeIdentifier(stateID, "stateId")
	if err != nil {
		return nil, err
	}
	key := stateSummaryKey(stateID)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing state convergence: %w", err)
	}
	if len(existing) > 0 {
		return nil, fmt.Errorf("state %s already declared converged", stateID)
	}
	if strings.TrimSpace(payload) == "" {
		return nil, errors.New("payload is required")
	}
	summary := &ConvergenceSummary{
		Scope:      "state",
		TargetID:   stateID,
		DeclaredBy: trainer.NodeID,
		DeclaredAt: time.Now().UTC().Format(time.RFC3339),
		Payload:    payload,
	}
	bytes, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(key, bytes); err != nil {
		return nil, err
	}
	return summary, nil
}

// DeclareNationConvergence marks the nation as converged (first declaration wins).
func (c *GatewayContract) DeclareNationConvergence(ctx contractapi.TransactionContextInterface, payload string) (*ConvergenceSummary, error) {
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
		return nil, err
	}
	key := nationSummaryKey()
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("failed to read nation convergence: %w", err)
	}
	if len(existing) > 0 {
		return nil, errors.New("nation convergence already declared")
	}
	if strings.TrimSpace(payload) == "" {
		return nil, errors.New("payload is required")
	}
	summary := &ConvergenceSummary{
		Scope:      "nation",
		TargetID:   "nation",
		DeclaredBy: trainer.NodeID,
		DeclaredAt: time.Now().UTC().Format(time.RFC3339),
		Payload:    payload,
	}
	bytes, err := json.Marshal(summary)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(key, bytes); err != nil {
		return nil, err
	}
	return summary, nil
}

// ReadStateConvergence loads convergence information for a specific state.
func (c *GatewayContract) ReadStateConvergence(ctx contractapi.TransactionContextInterface, stateID string) (*StateConvergence, error) {
	stateID, err := normalizeIdentifier(stateID, "stateId")
	if err != nil {
		return nil, err
	}
	result := &StateConvergence{
		StateID:  stateID,
		Clusters: map[string]*ConvergenceRecord{},
	}
	prefix := fmt.Sprintf("%s%s:", stateConvPrefix, stateID)
	iter, err := ctx.GetStub().GetStateByRange(prefix, prefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to read state convergence: %w", err)
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		if strings.HasSuffix(kv.Key, ":summary") {
			var summary ConvergenceSummary
			if err := json.Unmarshal(kv.Value, &summary); err != nil {
				return nil, err
			}
			result.Summary = &summary
			continue
		}
		if !strings.Contains(kv.Key, ":cluster:") {
			continue
		}
		var record ConvergenceRecord
		if err := json.Unmarshal(kv.Value, &record); err != nil {
			return nil, err
		}
		if record.ClusterID == "" {
			continue
		}
		result.Clusters[record.ClusterID] = &record
	}
	return result, nil
}

// ListStateConvergence returns convergence info for all states.
func (c *GatewayContract) ListStateConvergence(ctx contractapi.TransactionContextInterface) (map[string]*StateConvergence, error) {
	results := map[string]*StateConvergence{}
	iter, err := ctx.GetStub().GetStateByRange(stateConvPrefix, stateConvPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to list state convergence: %w", err)
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		stateID, kind, clusterID := parseStateConvergenceKey(kv.Key)
		if stateID == "" {
			continue
		}
		state, ok := results[stateID]
		if !ok {
			state = &StateConvergence{
				StateID:  stateID,
				Clusters: map[string]*ConvergenceRecord{},
			}
			results[stateID] = state
		}
		switch kind {
		case "summary":
			var summary ConvergenceSummary
			if err := json.Unmarshal(kv.Value, &summary); err != nil {
				return nil, err
			}
			state.Summary = &summary
		case "cluster":
			var record ConvergenceRecord
			if err := json.Unmarshal(kv.Value, &record); err != nil {
				return nil, err
			}
			if clusterID == "" {
				clusterID = record.ClusterID
			}
			state.Clusters[clusterID] = &record
		}
	}
	return results, nil
}

// ReadNationConvergence returns the convergence status for the nation.
func (c *GatewayContract) ReadNationConvergence(ctx contractapi.TransactionContextInterface) (*NationConvergence, error) {
	return c.listNationConvergence(ctx)
}

// ListNationConvergence exposes the detailed nation convergence map.
func (c *GatewayContract) ListNationConvergence(ctx contractapi.TransactionContextInterface) (*NationConvergence, error) {
	return c.listNationConvergence(ctx)
}

func (c *GatewayContract) listNationConvergence(ctx contractapi.TransactionContextInterface) (*NationConvergence, error) {
	result := &NationConvergence{
		States: map[string]*ConvergenceRecord{},
	}
	iter, err := ctx.GetStub().GetStateByRange(nationConvPrefix, nationConvPrefix+"~")
	if err != nil {
		return nil, fmt.Errorf("failed to list nation convergence: %w", err)
	}
	defer iter.Close()
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		switch kind, stateID := parseNationConvergenceKey(kv.Key); kind {
		case "summary":
			var summary ConvergenceSummary
			if err := json.Unmarshal(kv.Value, &summary); err != nil {
				return nil, err
			}
			result.Summary = &summary
		case "state":
			var record ConvergenceRecord
			if err := json.Unmarshal(kv.Value, &record); err != nil {
				return nil, err
			}
			if stateID == "" {
				stateID = record.StateID
			}
			result.States[stateID] = &record
		}
	}
	return result, nil
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

func modelScopeRoundKey(layer, scope string, round int) string {
	return fmt.Sprintf("%s%s:%s:%d", modelScopeRoundPrefix, layer, scope, round)
}

func whitelistKey(jwtSub string) string {
	return whitelistPrefix + strings.ToLower(strings.TrimSpace(jwtSub))
}

func stateClusterKey(stateID, clusterID string) string {
	return fmt.Sprintf("%s%s:cluster:%s", stateConvPrefix, stateID, clusterID)
}

func stateSummaryKey(stateID string) string {
	return fmt.Sprintf("%s%s:summary", stateConvPrefix, stateID)
}

func nationStateKey(stateID string) string {
	return fmt.Sprintf("%sstate:%s", nationConvPrefix, stateID)
}

func nationSummaryKey() string {
	return nationConvPrefix + "summary"
}

func normalizeIdentifier(value, field string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(value))
	if v == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	return v, nil
}

func parseRound(raw string, required bool) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		if required {
			return 0, errors.New("round is required")
		}
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, fmt.Errorf("round must be an integer: %w", err)
	}
	if value < 1 {
		return 0, errors.New("round must be >= 1")
	}
	return value, nil
}

func parseStateConvergenceKey(key string) (stateID, kind, clusterID string) {
	if !strings.HasPrefix(key, stateConvPrefix) {
		return "", "", ""
	}
	remainder := strings.TrimPrefix(key, stateConvPrefix)
	parts := strings.Split(remainder, ":")
	if len(parts) == 0 {
		return "", "", ""
	}
	stateID = parts[0]
	if len(parts) == 1 {
		return stateID, "", ""
	}
	if parts[1] == "summary" {
		return stateID, "summary", ""
	}
	if parts[1] == "cluster" && len(parts) >= 3 {
		clusterID = strings.Join(parts[2:], ":")
		return stateID, "cluster", clusterID
	}
	return stateID, "", ""
}

func parseNationConvergenceKey(key string) (kind, stateID string) {
	if !strings.HasPrefix(key, nationConvPrefix) {
		return "", ""
	}
	remainder := strings.TrimPrefix(key, nationConvPrefix)
	parts := strings.Split(remainder, ":")
	if len(parts) == 0 {
		return "", ""
	}
	if parts[0] == "summary" {
		return "summary", ""
	}
	if parts[0] == "state" && len(parts) >= 2 {
		stateID = strings.Join(parts[1:], ":")
		return "state", stateID
	}
	return "", ""
}
