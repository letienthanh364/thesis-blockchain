package registry

import (
	"encoding/json"
	"net/http"

	"github.com/nebula/api-gateway/internal/common"
)

// HTTPHandler exposes registry endpoints.
type HTTPHandler struct {
	svc *Service
}

// NewHTTPHandler wires a registry HTTP handler.
func NewHTTPHandler(svc *Service) *HTTPHandler {
	return &HTTPHandler{svc: svc}
}

// RegisterRoutes mounts the enrollment endpoint.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux, auth *common.Authenticator) {
	mux.Handle("/auth/register-trainer", auth.RequireAuth(http.HandlerFunc(h.handleRegister)))
}

type registerRequest struct {
	DID        string          `json:"did"`
	NodeID     string          `json:"nodeId"`
	VC         json.RawMessage `json:"vc"`
	PublicKey  string          `json:"public_key"`
	PublicKey2 string          `json:"publicKey"`
}

func (r *registerRequest) toInput() RegisterInput {
	key := r.PublicKey
	if key == "" {
		key = r.PublicKey2
	}
	return RegisterInput{
		DID:       r.DID,
		NodeID:    r.NodeID,
		VC:        r.VC,
		PublicKey: key,
	}
}

func (h *HTTPHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	var payload registerRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		common.WriteErrorWithCode(w, http.StatusBadRequest, err)
		return
	}
	authCtx, ok := common.AuthContextFrom(r.Context())
	if !ok {
		common.WriteErrorWithCode(w, http.StatusUnauthorized, common.ErrMissingAuthContext)
		return
	}
	record, err := h.svc.Register(r.Context(), authCtx, payload.toInput())
	if err != nil {
		status := http.StatusInternalServerError
		if se, ok := common.AsStatusError(err); ok {
			status = se.Code
		}
		common.WriteErrorWithCode(w, status, err)
		return
	}
	common.WriteJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"jwt_sub":          record.JWTSub,
		"fabric_client_id": record.FabricClientID,
		"vc_hash":          record.VCHash,
		"did":              record.DID,
		"node_id":          record.NodeID,
		"registered_at":    record.RegisteredAt,
	})
}
