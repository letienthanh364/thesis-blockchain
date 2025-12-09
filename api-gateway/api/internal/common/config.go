package common

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// Config captures all runtime settings used by the API gateway.
type Config struct {
	Channel         string
	Chaincode       string
	MSPID           string
	OrgCryptoPath   string
	AdminIdentity   string
	AdminMSPPath    string
	OrdererEndpoint string
	OrdererHost     string
	OrdererTLSCA    string
	FabricCfgPath   string
	Peers           map[string]PeerConfig
	DefaultPeer     string
	AuthSecret      string
	TrainerDBPath   string
	AdminPublicKey  []byte
	JobID           string

	mspCache map[string]string
	mspMu    sync.RWMutex
}

// PeerConfig captures the TLS material and address for an endorsing peer.
type PeerConfig struct {
	Name    string
	Address string
	TLSPath string
}

// LoadConfig builds a Config instance from environment variables.
func LoadConfig() (*Config, error) {
	channel := fallbackEnv("FABRIC_CHANNEL", "nebulachannel")
	chaincode := fallbackEnv("FABRIC_CHAINCODE", "basic")
	mspID := fallbackEnv("MSP_ID", "Org1MSP")
	orgPath := os.Getenv("ORG_CRYPTO_PATH")
	if orgPath == "" {
		return nil, errors.New("ORG_CRYPTO_PATH must be set")
	}
	admin := fallbackEnv("ADMIN_IDENTITY", "Admin@org1.nebula.com")
	adminMSPPath := fmt.Sprintf("%s/users/%s/msp", orgPath, admin)
	ordererEndpoint := fallbackEnv("ORDERER_ENDPOINT", "orderer.nebula.com:7050")
	ordererTLS := fallbackEnv("ORDERER_TLS_CA", "/organizations/ordererOrganizations/nebula.com/orderers/orderer.nebula.com/msp/tlscacerts/tlsca.nebula.com-cert.pem")
	peerDomain := fallbackEnv("ORG_DOMAIN", "org1.nebula.com")
	fabricCfgPath := fallbackEnv("FABRIC_CFG_PATH", "/etc/hyperledger/fabric")
	trainerDBPath := fallbackEnv("TRAINER_DB_PATH", "/data/trainers.json")
	adminKey, err := parseAdminKey(os.Getenv("ADMIN_PUBLIC_KEY"))
	if err != nil {
		return nil, err
	}
	peers, err := parsePeerConfig(os.Getenv("PEER_ENDPOINTS"), orgPath, peerDomain)
	if err != nil {
		return nil, err
	}
	defaultPeer := fallbackEnv("DEFAULT_PEER", "")
	if defaultPeer == "" {
		defaultPeer = "peer0"
	}
	if _, ok := peers[defaultPeer]; !ok {
		for name := range peers {
			defaultPeer = name
			break
		}
	}
	authSecret := os.Getenv("AUTH_JWT_SECRET")
	if authSecret == "" {
		return nil, errors.New("AUTH_JWT_SECRET must be set")
	}
	host, _, found := strings.Cut(ordererEndpoint, ":")
	if !found || host == "" {
		host = ordererEndpoint
	}

	return &Config{
		Channel:         channel,
		Chaincode:       chaincode,
		MSPID:           mspID,
		OrgCryptoPath:   orgPath,
		AdminIdentity:   admin,
		AdminMSPPath:    adminMSPPath,
		OrdererEndpoint: ordererEndpoint,
		OrdererHost:     host,
		OrdererTLSCA:    ordererTLS,
		FabricCfgPath:   fabricCfgPath,
		Peers:           peers,
		DefaultPeer:     defaultPeer,
		AuthSecret:      authSecret,
		TrainerDBPath:   trainerDBPath,
		AdminPublicKey:  adminKey,
		JobID:           os.Getenv("GATEWAY_JOB_ID"),
		mspCache:        map[string]string{},
	}, nil
}

func parseAdminKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("ADMIN_PUBLIC_KEY must be provided (base64 encoded Ed25519 key)")
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to decode ADMIN_PUBLIC_KEY: %w", err)
	}
	if l := len(key); l != 32 {
		return nil, fmt.Errorf("ADMIN_PUBLIC_KEY must be 32 bytes for ed25519, got %d", l)
	}
	return key, nil
}

func parsePeerConfig(spec, orgPath, domain string) (map[string]PeerConfig, error) {
	if spec == "" {
		return nil, errors.New("PEER_ENDPOINTS must be provided")
	}
	entries := strings.Split(spec, ",")
	peers := make(map[string]PeerConfig, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.Split(entry, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid peer entry %s", entry)
		}
		name := parts[0]
		addr := parts[1]
		tlsPath := fmt.Sprintf("%s/peers/%s.%s/tls/ca.crt", orgPath, name, domain)
		peers[name] = PeerConfig{Name: name, Address: addr, TLSPath: tlsPath}
	}
	if len(peers) == 0 {
		return nil, errors.New("no peers configured")
	}
	return peers, nil
}

// MSPPathForIdentity resolves the MSP folder for the requested Fabric identity.
func (c *Config) MSPPathForIdentity(identity string) (string, error) {
	c.mspMu.RLock()
	if path, ok := c.mspCache[identity]; ok {
		c.mspMu.RUnlock()
		return path, nil
	}
	c.mspMu.RUnlock()

	var path string
	if identity == "" || identity == c.AdminIdentity {
		path = c.AdminMSPPath
	} else {
		path = fmt.Sprintf("%s/users/%s/msp", c.OrgCryptoPath, identity)
	}
	if _, err := os.Stat(path); err != nil {
		return "", fmt.Errorf("fabric identity %s not found at %s: %w", identity, path, err)
	}
	c.mspMu.Lock()
	c.mspCache[identity] = path
	c.mspMu.Unlock()
	return path, nil
}

func fallbackEnv(key, fallback string) string {
	val := os.Getenv(key)
	if val == "" {
		return fallback
	}
	return val
}
