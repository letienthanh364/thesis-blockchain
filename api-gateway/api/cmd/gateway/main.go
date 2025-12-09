package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/nebula/api-gateway/internal/common"
	"github.com/nebula/api-gateway/internal/data"
	"github.com/nebula/api-gateway/internal/registry"
)

func main() {
	cfg, err := common.LoadConfig()
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	fabric := common.NewFabricClient(cfg)
	if err := fabric.WaitForChannelReady(2 * time.Minute); err != nil {
		log.Fatalf("fabric channel not ready: %v", err)
	}
	store, err := registry.NewStore(cfg.TrainerDBPath)
	if err != nil {
		log.Fatalf("failed to initialize trainer store: %v", err)
	}
	verifier, err := registry.NewVCVerifier(cfg.AdminPublicKey, cfg.JobID)
	if err != nil {
		log.Fatalf("failed to initialize VC verifier: %v", err)
	}
	auth, err := common.NewAuthenticator(cfg.AuthSecret)
	if err != nil {
		log.Fatalf("failed to initialize authenticator: %v", err)
	}

	regSvc := registry.NewService(cfg, fabric, store, verifier)
	dataSvc := data.NewService(cfg, fabric, store)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler(cfg))
	registry.NewHTTPHandler(regSvc).RegisterRoutes(mux, auth)
	data.NewHTTPHandler(dataSvc, store).RegisterRoutes(mux, auth)

	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}
	addr := fmt.Sprintf(":%s", port)
	log.Printf("api gateway listening on %s", addr)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func healthHandler(cfg *common.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		common.WriteJSON(w, http.StatusOK, map[string]any{
			"status":       "ok",
			"chaincode":    cfg.Chaincode,
			"default_peer": cfg.DefaultPeer,
			"job_id":       cfg.JobID,
		})
	}
}
