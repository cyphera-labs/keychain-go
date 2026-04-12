package keychain

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// EnvProvider resolves keys from environment variables.
// Variables are named as PREFIX_REF_KEY (uppercase, hyphens replaced with underscores).
type EnvProvider struct {
	prefix string
}

// NewEnvProvider creates a provider that reads keys from env vars with the given prefix.
func NewEnvProvider(prefix string) *EnvProvider {
	return &EnvProvider{prefix: prefix}
}

func (p *EnvProvider) Resolve(ref string) (KeyRecord, error) {
	varName := p.envVarName(ref)
	val := os.Getenv(varName)
	if val == "" {
		return KeyRecord{}, fmt.Errorf("%w: env var %s not set", ErrKeyNotFound, varName)
	}
	material, err := hex.DecodeString(strings.TrimSpace(val))
	if err != nil {
		return KeyRecord{}, fmt.Errorf("invalid hex in env var %s: %w", varName, err)
	}
	return KeyRecord{
		Ref:       ref,
		Version:   1,
		Status:    StatusActive,
		Material:  material,
		CreatedAt: time.Now(),
	}, nil
}

func (p *EnvProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	return p.Resolve(ref) // env vars don't support versioning
}

func (p *EnvProvider) envVarName(ref string) string {
	name := strings.ToUpper(strings.ReplaceAll(ref, "-", "_"))
	if p.prefix != "" {
		return p.prefix + "_" + name
	}
	return name
}
