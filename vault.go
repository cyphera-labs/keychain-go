package keychain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VaultProvider resolves keys from HashiCorp Vault KV v2 secrets.
type VaultProvider struct {
	address string
	token   string
	mount   string
	client  *http.Client
}

// NewVaultProvider creates a Vault key provider.
func NewVaultProvider(address, token string, mount ...string) *VaultProvider {
	m := "secret"
	if len(mount) > 0 && mount[0] != "" {
		m = mount[0]
	}
	return &VaultProvider{
		address: address,
		token:   token,
		mount:   m,
		client:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (p *VaultProvider) Resolve(ref string) (KeyRecord, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", p.address, p.mount, ref)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return KeyRecord{}, err
	}
	req.Header.Set("X-Vault-Token", p.token)

	resp, err := p.client.Do(req)
	if err != nil {
		return KeyRecord{}, fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return KeyRecord{}, fmt.Errorf("%w: %s", ErrKeyNotFound, ref)
	}
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return KeyRecord{}, fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return KeyRecord{}, fmt.Errorf("failed to decode vault response: %w", err)
	}

	materialStr, ok := result.Data.Data["material"].(string)
	if !ok {
		return KeyRecord{}, fmt.Errorf("vault secret %s missing 'material' field", ref)
	}
	material, err := hex.DecodeString(materialStr)
	if err != nil {
		return KeyRecord{}, fmt.Errorf("invalid hex material in vault secret %s: %w", ref, err)
	}

	version := 1
	if v, ok := result.Data.Data["version"].(float64); ok {
		version = int(v)
	}
	status := StatusActive
	if s, ok := result.Data.Data["status"].(string); ok {
		status = Status(s)
	}
	algorithm := ""
	if a, ok := result.Data.Data["algorithm"].(string); ok {
		algorithm = a
	}
	var tweak []byte
	if t, ok := result.Data.Data["tweak"].(string); ok && t != "" {
		tweak, _ = hex.DecodeString(t)
	}

	return KeyRecord{
		Ref:       ref,
		Version:   version,
		Status:    status,
		Algorithm: algorithm,
		Material:  material,
		Tweak:     tweak,
		CreatedAt: time.Now(),
	}, nil
}

func (p *VaultProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	// Vault KV v2 supports versions via ?version= query param
	// For now, delegate to Resolve (returns latest)
	return p.Resolve(ref)
}
