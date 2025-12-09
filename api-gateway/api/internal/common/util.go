package common

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// MustJSON marshals the payload or panics if it fails (programming error).
func MustJSON(v any) string {
	payload, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(payload)
}

// SanitizeCLIError trims peer CLI noise to a concise message.
func SanitizeCLIError(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return "unknown peer error"
	}
	if idx := strings.LastIndex(msg, "Error:"); idx != -1 {
		return strings.TrimSpace(msg[idx+6:])
	}
	return msg
}

// EnsureDir makes sure the parent directory for the provided file path exists.
func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o755)
}

// AtomicWriteFile writes data to a temp file and renames it into place.
func AtomicWriteFile(path string, data []byte, perm fs.FileMode) error {
	if err := EnsureDir(path); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
