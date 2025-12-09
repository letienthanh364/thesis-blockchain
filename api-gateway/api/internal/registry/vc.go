package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// VCVerifier checks the VC signature and computes the canonical hash.
type VCVerifier struct {
	adminKey ed25519.PublicKey
	jobID    string
}

// VerifiedVC includes the parsed credential metadata and hash.
type VerifiedVC struct {
	Subject    string
	JobID      string
	ValidFrom  time.Time
	ValidUntil time.Time
	Hash       string
}

// NewVCVerifier instantiates a verifier.
func NewVCVerifier(adminKey []byte, jobID string) (*VCVerifier, error) {
	if l := len(adminKey); l != ed25519.PublicKeySize {
		return nil, fmt.Errorf("admin public key must be %d bytes", ed25519.PublicKeySize)
	}
	key := make([]byte, len(adminKey))
	copy(key, adminKey)
	return &VCVerifier{adminKey: ed25519.PublicKey(key), jobID: jobID}, nil
}

// Verify validates the VC contents, returning the canonical hash.
func (v *VCVerifier) Verify(vc json.RawMessage, did string) (*VerifiedVC, error) {
	if len(vc) == 0 {
		return nil, errors.New("vc payload is required")
	}
	var document map[string]any
	if err := json.Unmarshal(vc, &document); err != nil {
		return nil, fmt.Errorf("invalid vc json: %w", err)
	}
	sigValue, ok := document["signature"].(string)
	if !ok || strings.TrimSpace(sigValue) == "" {
		return nil, errors.New("vc missing signature field")
	}
	delete(document, "signature")
	canonicalWithoutSig, err := Canonicalize(document)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize vc: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sigValue)
	if err != nil {
		return nil, fmt.Errorf("invalid vc signature encoding: %w", err)
	}
	if !ed25519.Verify(v.adminKey, canonicalWithoutSig, sigBytes) {
		return nil, errors.New("vc signature does not match admin key")
	}
	document["signature"] = sigValue
	canonicalWithSig, err := Canonicalize(document)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize signed vc: %w", err)
	}
	hash := sha256.Sum256(canonicalWithSig)

	var parsed struct {
		Subject    string `json:"subject"`
		JobID      string `json:"job_id"`
		ValidFrom  string `json:"valid_from"`
		ValidUntil string `json:"valid_until"`
	}
	if err := json.Unmarshal(canonicalWithSig, &parsed); err != nil {
		return nil, fmt.Errorf("failed to parse vc payload: %w", err)
	}
	if parsed.Subject == "" {
		return nil, errors.New("vc subject is required")
	}
	if strings.TrimSpace(parsed.Subject) != strings.TrimSpace(did) {
		return nil, errors.New("vc subject does not match requested did")
	}
	if v.jobID != "" && v.jobID != parsed.JobID {
		return nil, fmt.Errorf("vc job_id %s does not match expected %s", parsed.JobID, v.jobID)
	}
	validFrom, err := time.Parse(time.RFC3339, parsed.ValidFrom)
	if err != nil {
		return nil, fmt.Errorf("invalid valid_from: %w", err)
	}
	validUntil, err := time.Parse(time.RFC3339, parsed.ValidUntil)
	if err != nil {
		return nil, fmt.Errorf("invalid valid_until: %w", err)
	}
	now := time.Now().UTC()
	if now.Before(validFrom) {
		return nil, errors.New("vc not yet valid")
	}
	if now.After(validUntil) {
		return nil, errors.New("vc expired")
	}
	return &VerifiedVC{
		Subject:    parsed.Subject,
		JobID:      parsed.JobID,
		ValidFrom:  validFrom,
		ValidUntil: validUntil,
		Hash:       hex.EncodeToString(hash[:]),
	}, nil
}

// Canonicalize encodes a JSON value with deterministic ordering and no whitespace.
func Canonicalize(v any) ([]byte, error) {
	normalized, err := normalize(v)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(nil)
	if err := writeCanonical(buf, normalized); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func normalize(v any) (any, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		normalized := make(map[string]any, len(val))
		for k, v := range val {
			n, err := normalize(v)
			if err != nil {
				return nil, err
			}
			normalized[k] = n
		}
		return normalized, nil
	case []interface{}:
		out := make([]any, len(val))
		for i, v := range val {
			n, err := normalize(v)
			if err != nil {
				return nil, err
			}
			out[i] = n
		}
		return out, nil
	case json.Number:
		return val, nil
	case string, float64, bool, nil:
		return val, nil
	default:
		encoded, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		var decoded any
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			return nil, err
		}
		return normalize(decoded)
	}
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch val := v.(type) {
	case map[string]any:
		buf.WriteByte('{')
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			keyBytes, _ := json.Marshal(k)
			buf.Write(keyBytes)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, elem := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, elem); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case json.Number:
		buf.WriteString(val.String())
	case string:
		data, _ := json.Marshal(val)
		buf.Write(data)
	case float64, bool, nil:
		data, _ := json.Marshal(val)
		buf.Write(data)
	default:
		data, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(data)
	}
	return nil
}
