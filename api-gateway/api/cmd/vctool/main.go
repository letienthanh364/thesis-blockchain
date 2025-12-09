package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"

	"github.com/nebula/api-gateway/internal/registry"
)

func main() {
	var (
		vcPath  string
		keyPath string
		outPath string
	)
	flag.StringVar(&vcPath, "vc", "", "Path to the VC JSON file (without signature)")
	flag.StringVar(&keyPath, "key", "", "Path to the admin Ed25519 private key (PEM)")
	flag.StringVar(&outPath, "out", "", "Output file for the signed VC (defaults to stdout)")
	flag.Parse()

	if vcPath == "" || keyPath == "" {
		fatalf("both -vc and -key are required")
	}

	vcBytes, err := os.ReadFile(vcPath)
	if err != nil {
		fatalf("failed to read VC: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(vcBytes, &document); err != nil {
		fatalf("invalid VC JSON: %v", err)
	}
	delete(document, "signature")

	canonical, err := registry.Canonicalize(document)
	if err != nil {
		fatalf("failed to canonicalize VC: %v", err)
	}

	privKey, err := loadEd25519PrivateKey(keyPath)
	if err != nil {
		fatalf("failed to load private key: %v", err)
	}

	signature := ed25519.Sign(privKey, canonical)
	document["signature"] = base64.StdEncoding.EncodeToString(signature)

	signed, err := registry.Canonicalize(document)
	if err != nil {
		fatalf("failed to canonicalize signed VC: %v", err)
	}

	if outPath == "" {
		if _, err := os.Stdout.Write(signed); err != nil {
			fatalf("failed to write signed VC: %v", err)
		}
		return
	}
	if err := os.WriteFile(outPath, signed, 0o600); err != nil {
		fatalf("failed to write signed VC: %v", err)
	}
}

func loadEd25519PrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key in %s is not an Ed25519 private key", path)
	}
	return priv, nil
}

func fatalf(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
