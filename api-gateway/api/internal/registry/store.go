package registry

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"

	"github.com/nebula/api-gateway/internal/common"
)

// TrainerRecord represents a verified trainer enrollment persisted by the gateway.
type TrainerRecord struct {
	JWTSub         string `json:"jwt_sub"`
	FabricClientID string `json:"fabric_client_id"`
	DID            string `json:"did"`
	NodeID         string `json:"node_id"`
	VCHash         string `json:"vc_hash"`
	PublicKey      string `json:"public_key"`
	RegisteredAt   string `json:"registered_at"`
}

// Store keeps trainer enrollments on disk so they can be reused across restarts.
type Store struct {
	path       string
	mu         sync.RWMutex
	byJWT      map[string]*TrainerRecord
	byFabricID map[string]*TrainerRecord
}

// NewStore loads existing records from disk, creating an empty store if the file doesn't exist.
func NewStore(path string) (*Store, error) {
	s := &Store{
		path:       path,
		byJWT:      map[string]*TrainerRecord{},
		byFabricID: map[string]*TrainerRecord{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var records []*TrainerRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return err
	}
	for _, rec := range records {
		if rec == nil || rec.JWTSub == "" {
			continue
		}
		s.byJWT[rec.JWTSub] = rec
		if rec.FabricClientID != "" {
			s.byFabricID[rec.FabricClientID] = rec
		}
	}
	return nil
}

// Save stores/updates a trainer enrollment.
func (s *Store) Save(record *TrainerRecord) error {
	if record == nil || record.JWTSub == "" {
		return errors.New("invalid trainer record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.byFabricID[record.FabricClientID]; ok && existing.JWTSub != record.JWTSub {
		return errors.New("fabric identity already assigned to another trainer")
	}
	s.byJWT[record.JWTSub] = record
	if record.FabricClientID != "" {
		s.byFabricID[record.FabricClientID] = record
	}
	return s.persistLocked()
}

// FindByJWTSub returns the enrollment for the provided JWT subject.
func (s *Store) FindByJWTSub(jwtSub string) (*TrainerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.byJWT[jwtSub]
	if !ok {
		return nil, false
	}
	clone := *rec
	return &clone, true
}

func (s *Store) persistLocked() error {
	list := make([]*TrainerRecord, 0, len(s.byJWT))
	for _, rec := range s.byJWT {
		list = append(list, rec)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].JWTSub < list[j].JWTSub
	})
	payload, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return common.AtomicWriteFile(s.path, payload, 0o600)
}
