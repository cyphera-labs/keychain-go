package keychain

import (
	"fmt"
	"os"
	"sync"
)

// ProviderFactory creates a KeyProvider from config.
type ProviderFactory func(config map[string]string) (KeyProvider, error)

var (
	factoryMu   sync.RWMutex
	factories   = map[string]ProviderFactory{}
)

// RegisterFactory registers a provider factory for a given source type.
// Called by cloud provider files via init() when their build tag is active.
func RegisterFactory(source string, factory ProviderFactory) {
	factoryMu.Lock()
	defer factoryMu.Unlock()
	factories[source] = factory
}

// Resolve is the bridge function called by the Cyphera SDK when
// cyphera.json has "source" set to a cloud provider.
// Returns raw key bytes.
func Resolve(source string, config map[string]string) ([]byte, error) {
	ref := firstNonEmpty(config["ref"], config["path"], config["arn"], config["key"], "default")

	provider, err := createProvider(source, config)
	if err != nil {
		return nil, err
	}

	record, err := provider.Resolve(ref)
	if err != nil {
		return nil, fmt.Errorf("keychain resolution failed for source '%s': %w", source, err)
	}
	return record.Material, nil
}

func createProvider(source string, config map[string]string) (KeyProvider, error) {
	// Built-in providers (always available)
	switch source {
	case "vault":
		addr := firstNonEmpty(config["addr"], os.Getenv("VAULT_ADDR"), "http://127.0.0.1:8200")
		token := firstNonEmpty(config["token"], os.Getenv("VAULT_TOKEN"))
		mount := firstNonEmpty(config["mount"], "secret")
		return NewVaultProvider(addr, token, mount), nil
	}

	// Cloud providers (require build tags)
	factoryMu.RLock()
	factory, ok := factories[source]
	factoryMu.RUnlock()

	if ok {
		return factory(config)
	}

	hints := map[string]string{
		"aws-kms":  "go build -tags aws",
		"gcp-kms":  "go build -tags gcp",
		"azure-kv": "go build -tags azure",
	}
	if hint, ok := hints[source]; ok {
		return nil, fmt.Errorf("source '%s' requires a build tag: %s", source, hint)
	}

	return nil, fmt.Errorf("unknown source: %s", source)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
