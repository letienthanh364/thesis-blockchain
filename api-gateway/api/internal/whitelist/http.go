package whitelist

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/nebula/api-gateway/internal/common"
)

// HTTPHandler exposes whitelist routes.
type HTTPHandler struct {
	svc *Service
}

// NewHTTPHandler builds a handler for whitelist operations.
func NewHTTPHandler(svc *Service) *HTTPHandler {
	return &HTTPHandler{svc: svc}
}

// RegisterRoutes mounts the `/whitelist` endpoint.
func (h *HTTPHandler) RegisterRoutes(mux *http.ServeMux, auth *common.Authenticator) {
	mux.Handle("/whitelist", auth.RequireAuth(http.HandlerFunc(h.handleList), common.RoleAggregator, common.RoleAdmin))
}

func (h *HTTPHandler) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		common.WriteErrorWithCode(w, http.StatusMethodNotAllowed, common.ErrMethodNotAllowed)
		return
	}
	page := 1
	perPage := defaultPageSize
	if raw := strings.TrimSpace(r.URL.Query().Get("page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "page must be a positive integer"))
			return
		}
		page = value
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("per_page")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			common.WriteErrorWithCode(w, http.StatusBadRequest, common.NewStatusError(http.StatusBadRequest, "per_page must be a positive integer"))
			return
		}
		perPage = value
	}
	result, err := h.svc.List(r.Context(), page, perPage)
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
