package common

import (
	"encoding/json"
	"log"
	"net/http"
)

// WriteJSON serializes payload as JSON with the provided status code.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// WriteError write a 500 error response.
func WriteError(w http.ResponseWriter, err error) {
	WriteErrorWithCode(w, http.StatusInternalServerError, err)
}

// WriteErrorWithCode logs and responds with the provided status code.
func WriteErrorWithCode(w http.ResponseWriter, code int, err error) {
	log.Printf("error: %v", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}
