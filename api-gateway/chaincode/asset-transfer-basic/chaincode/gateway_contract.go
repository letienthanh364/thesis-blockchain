package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"
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

// DataRecord describes committed payloads.
type DataRecord struct {
	ID          string `json:"id"`
	Owner       string `json:"owner"`
	Payload     string `json:"payload"`
	SubmittedAt string `json:"submitted_at"`
}

const (
	trainerPrefix = "trainer:"
	dataPrefix    = "data:"
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
	trainer, err := c.requireAuthorizedTrainer(ctx)
	if err != nil {
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
	if record.Owner != trainer.NodeID {
		return nil, errTrainerUnauthorized
	}
	return &record, nil
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
