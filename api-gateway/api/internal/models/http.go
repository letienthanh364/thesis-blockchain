package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/nebula/api-gateway/internal/common"
	"github.com/nebula/api-gateway/internal/registry"
)

// HTTPHandler exposes the scoped /models endpoints.
type HTTPHandler struct {
	svc   *Service
	store *registry.Store
}

// NewHTTPHandler prepares a HTTP handler.
func NewHTTPHandler(svc *Service, store *registry.Store) *HTTPHandler {
	return &HTTPHandler{svc: svc, store: store}
}

// RegisterRoutes wires the models endpoints for each configured layer.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux, auth *common.Authenticator) {
	keyFunc := func(header *common.TokenHeader, claims *common.JWTClaims) (*common.KeySpec, error) {
		subject := strings.TrimSpace(claims.Subject)
		if subject == "" {
			return nil, errors.New("token missing subject")
		}
		record, ok := h.store.FindByJWTSub(subject)
		if !ok {
			return nil, errors.New("trainer not registered")
		}
		pub, err := record.PublicKeyBytes()
		if err != nil {
			return nil, err
		}
		return &common.KeySpec{Algorithm: "EdDSA", PublicKey: pub}, nil
	}
	for _, layer := range h.svc.Layers() {
		if layer == nil {
			continue
		}
		layer := layer
		basePath := fmt.Sprintf("/%s/models", layer.Slug)
		mux.Handle(basePath, auth.RequireAuthWithKeyFunc(keyFunc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.handleCollection(w, r, layer)
		})))
		mux.Handle(basePath+"/latest", auth.RequireAuthWithKeyFunc(keyFunc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.handleLatest(w, r, layer)
		})))
		mux.Handle(basePath+"/", auth.RequireAuthWithKeyFunc(keyFunc, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.handleRecord(w, r, layer)
		})))
	}
}

func (h *HTTPHandler) handleCollection(w http.ResponseWriter, r *http.Request, layer *Layer) {
	switch r.Method {
	case http.MethodPost:
		h.handleCommit(w, r, layer)
	case http.MethodGet:
		h.handleList(w, r, layer)
	default:
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
	}
}

func (h *HTTPHandler) handleRecord(w http.ResponseWriter, r *http.Request, layer *Layer) {
	if r.Method != http.MethodGet {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	prefix := fmt.Sprintf("/%s/models/", layer.Slug)
	dataID := strings.TrimPrefix(r.URL.Path, prefix)
	if dataID == "" {
		common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "data identifier missing"))
		return
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	record, err := h.svc.Retrieve(r.Context(), authCtx, dataID)
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := common.AsStatusError(err); ok {
			status = se.Code
		}
		common.WriteErrorWithCode(w, status, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, record)
}

func (h *HTTPHandler) handleCommit(w http.ResponseWriter, r *http.Request, layer *Layer) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, err)
		return
	}
	payload := body["payload"]
	if len(payload) == 0 {
		common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "payload is required"))
		return
	}
	scopeID, err := extractScopeID(body, layer)
	if err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, err)
		return
	}
	round, err := extractRound(body, layer)
	if err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, err)
		return
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	result, err := h.svc.Commit(r.Context(), authCtx, layer.Slug, scopeID, round, payload)
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := common.AsStatusError(err); ok {
			status = se.Code
		}
		common.WriteErrorWithCode(w, status, err)
		return
	}
	common.WriteJSON(w, http.StatusCreated, result)
}

func (h *HTTPHandler) handleList(w http.ResponseWriter, r *http.Request, layer *Layer) {
	query := r.URL.Query()
	scopeID := extractScopeParam(query, layer)
	round, err := extractRoundQuery(query, layer)
	if err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, err.Error()))
		return
	}
	page := 1
	if raw := strings.TrimSpace(query.Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "page must be a positive integer"))
			return
		}
		page = value
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	if round > 0 {
		if scopeID == "" {
			common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, layer.ScopeLabel+" identifier is required when filtering by round"))
			return
		}
		record, err := h.svc.LookupByScopeRound(r.Context(), authCtx, layer.Slug, scopeID, round)
		if err != nil {
			status := http.StatusInternalServerError
			if se, ok := common.AsStatusError(err); ok {
				status = se.Code
			}
			common.WriteErrorWithCode(w, status, err)
			return
		}
		common.WriteJSON(w, http.StatusOK, record)
		return
	}
	result, err := h.svc.List(r.Context(), authCtx, layer.Slug, scopeID, page)
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := common.AsStatusError(err); ok {
			status = se.Code
		}
		common.WriteErrorWithCode(w, status, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, result)
}

func (h *HTTPHandler) handleLatest(w http.ResponseWriter, r *http.Request, layer *Layer) {
	if r.Method != http.MethodGet {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	scopeID := extractScopeParam(r.URL.Query(), layer)
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	record, err := h.svc.Latest(r.Context(), authCtx, layer.Slug, scopeID)
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := common.AsStatusError(err); ok {
			status = se.Code
		}
		common.WriteErrorWithCode(w, status, err)
		return
	}
	response, err := recordWithIdentity(record, layer)
	if err != nil {
		common.WriteErrorWithCode(w, http.StatusInternalServerError, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, response)
}

func extractScopeID(body map[string]json.RawMessage, layer *Layer) (string, error) {
	candidates := []string{layer.ScopeField, "scope_id", "scopeId"}
	for _, key := range candidates {
		if key == "" {
			continue
		}
		raw, ok := body[key]
		if !ok {
			continue
		}
		var scope string
		if err := json.Unmarshal(raw, &scope); err != nil {
			return "", common.NewStatusError(http.StatusBadRequest, fmt.Sprintf("%s must be a string", key))
		}
		scope = strings.TrimSpace(scope)
		if scope != "" {
			return scope, nil
		}
	}
	return "", nil
}

func extractScopeParam(values url.Values, layer *Layer) string {
	candidates := []string{"scopeId", "scope_id"}
	if layer != nil {
		if field := strings.TrimSpace(layer.ScopeField); field != "" {
			candidates = append(candidates, field)
		}
		if label := strings.TrimSpace(layer.ScopeLabel); label != "" {
			candidates = append(candidates, label)
		}
	}
	for _, key := range candidates {
		if key == "" {
			continue
		}
		value := strings.TrimSpace(values.Get(key))
		if value != "" {
			return value
		}
	}
	return ""
}

func extractRound(body map[string]json.RawMessage, layer *Layer) (int, error) {
	seen := map[string]struct{}{}
	for _, key := range roundKeyCandidates(layer) {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		raw, ok := body[key]
		if !ok {
			continue
		}
		round, err := parseRoundValue(raw, key)
		if err != nil {
			return 0, err
		}
		return round, nil
	}
	return 0, nil
}

func extractRoundQuery(values url.Values, layer *Layer) (int, error) {
	seen := map[string]struct{}{}
	for _, key := range roundKeyCandidates(layer) {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		raw := strings.TrimSpace(values.Get(key))
		if raw == "" {
			continue
		}
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, fmt.Errorf("%s must be a positive integer", key)
		}
		return value, nil
	}
	return 0, nil
}

func roundKeyCandidates(layer *Layer) []string {
	keys := []string{"round"}
	add := func(base string) {
		base = strings.TrimSpace(base)
		if base == "" {
			return
		}
		keys = append(keys, base+"_round", base+"-round")
	}
	if layer != nil {
		add(layer.ScopeLabel)
		add(layer.ScopeField)
	}
	return keys
}

func parseRoundValue(raw json.RawMessage, key string) (int, error) {
	var intVal int
	if err := json.Unmarshal(raw, &intVal); err == nil {
		if intVal < 1 {
			return 0, common.NewStatusError(http.StatusBadRequest, fmt.Sprintf("%s must be >= 1", key))
		}
		return intVal, nil
	}
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		if str == "" {
			return 0, common.NewStatusError(http.StatusBadRequest, fmt.Sprintf("%s must be >= 1", key))
		}
		value, err := strconv.Atoi(str)
		if err != nil || value < 1 {
			return 0, common.NewStatusError(http.StatusBadRequest, fmt.Sprintf("%s must be an integer", key))
		}
		return value, nil
	}
	return 0, common.NewStatusError(http.StatusBadRequest, fmt.Sprintf("%s must be a positive integer", key))
}

func recordWithIdentity(record *ModelRecord, layer *Layer) (map[string]interface{}, error) {
	if record == nil {
		return nil, errors.New("record is required")
	}
	bytes, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	payload := map[string]interface{}{}
	if err := json.Unmarshal(bytes, &payload); err != nil {
		return nil, err
	}
	if layer != nil {
		key := strings.TrimSpace(layer.ScopeField)
		if key == "" {
			key = strings.TrimSpace(layer.ScopeLabel)
		}
		if key != "" {
			payload[key] = record.ScopeID
		}
	}
	return payload, nil
}
