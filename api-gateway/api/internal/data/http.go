package data

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/nebula/api-gateway/internal/common"
	"github.com/nebula/api-gateway/internal/registry"
)

// HTTPHandler exposes the commit/retrieve endpoints.
type HTTPHandler struct {
	svc   *Service
	store *registry.Store
}

// NewHTTPHandler builds a handler.
func NewHTTPHandler(svc *Service, store *registry.Store) *HTTPHandler {
	return &HTTPHandler{svc: svc, store: store}
}

// RegisterRoutes mounts the handler on the mux.
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
	mux.Handle("/data/commit", auth.RequireAuthWithKeyFunc(keyFunc, http.HandlerFunc(h.handleCommit)))
	mux.Handle("/data/", auth.RequireAuthWithKeyFunc(keyFunc, http.HandlerFunc(h.handleRetrieve)))
}

type commitRequest struct {
	Payload json.RawMessage `json:"payload"`
}

func (h *HTTPHandler) handleCommit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	var payload commitRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, err)
		return
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	result, err := h.svc.Commit(r.Context(), authCtx, payload.Payload)
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

func (h *HTTPHandler) handleRetrieve(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	dataID := strings.TrimPrefix(r.URL.Path, "/data/")
	if dataID == "" {
		common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "data identifier missing"))
		return
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	result, err := h.svc.Retrieve(r.Context(), authCtx, dataID)
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
