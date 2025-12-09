package data

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nebula/api-gateway/internal/common"
)

// HTTPHandler exposes the commit/retrieve endpoints.
type HTTPHandler struct {
	svc *Service
}

// NewHTTPHandler builds a handler.
func NewHTTPHandler(svc *Service) *HTTPHandler {
	return &HTTPHandler{svc: svc}
}

// RegisterRoutes mounts the handler on the mux.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux, auth *common.Authenticator) {
	mux.Handle("/data/commit", auth.RequireAuth(http.HandlerFunc(h.handleCommit)))
	mux.Handle("/data/", auth.RequireAuth(http.HandlerFunc(h.handleRetrieve)))
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
