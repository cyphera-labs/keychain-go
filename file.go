package keychain

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// FileProvider resolves keys from a JSON file.
type FileProvider struct {
	records map[string][]KeyRecord
}

type fileKey struct {
	Ref       string `json:"ref"`
	Version   int    `json:"version"`
	Status    string `json:"status"`
	Algorithm string `json:"algorithm"`
	Material  string `json:"material"`
	Tweak     string `json:"tweak"`
}

type fileConfig struct {
	Keys []fileKey `json:"keys"`
}

// NewFileProvider loads keys from a JSON file.
func NewFileProvider(path string) (*FileProvider, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	var cfg fileConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse key file: %w", err)
	}
	p := &FileProvider{records: make(map[string][]KeyRecord)}
	for _, k := range cfg.Keys {
		material, err := decodeKeyMaterial(k.Material)
		if err != nil {
			return nil, fmt.Errorf("key %s: %w", k.Ref, err)
		}
		var tweak []byte
		if k.Tweak != "" {
			tweak, err = decodeKeyMaterial(k.Tweak)
			if err != nil {
				return nil, fmt.Errorf("key %s tweak: %w", k.Ref, err)
			}
		}
		status := StatusActive
		if k.Status != "" {
			status = Status(k.Status)
		}
		p.records[k.Ref] = append(p.records[k.Ref], KeyRecord{
			Ref:       k.Ref,
			Version:   k.Version,
			Status:    status,
			Algorithm: k.Algorithm,
			Material:  material,
			Tweak:     tweak,
			CreatedAt: time.Now(),
		})
	}
	return p, nil
}

func (p *FileProvider) Resolve(ref string) (KeyRecord, error) {
	versions, ok := p.records[ref]
	if !ok {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	}
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].Status == StatusActive {
			return versions[i], nil
		}
	}
	return KeyRecord{}, fmt.Errorf("%w: %s", ErrNoActiveKey, ref)
}

func (p *FileProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	versions, ok := p.records[ref]
	if !ok {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	}
	for _, r := range versions {
		if r.Version == version {
			if r.Status == StatusDisabled {
				return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyDisabled, ref, version)
			}
			return r, nil
		}
	}
	return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyNotFound, ref, version)
}

func decodeKeyMaterial(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("could not decode as hex or base64")
}
