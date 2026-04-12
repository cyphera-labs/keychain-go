package keychain

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// AzureKvProvider resolves keys using Azure Key Vault.
// Generates a random 32-byte AES key locally, wraps it with Key Vault's
// RSA-OAEP, and caches the plaintext per ref.
type AzureKvProvider struct {
	vaultURL string
	keyName  string
	client   AzureWrapKeyAPI
	cache    sync.Map
}

// AzureWrapKeyAPI is the subset of the Azure Key Vault client we need, enabling test mocks.
type AzureWrapKeyAPI interface {
	WrapKey(ctx context.Context, keyName string, keyVersion string, parameters azkeys.KeyOperationParameters, options *azkeys.WrapKeyOptions) (azkeys.WrapKeyResponse, error)
}

// NewAzureKvProvider creates an Azure Key Vault key provider.
// Uses DefaultAzureCredential for authentication.
func NewAzureKvProvider(vaultURL, keyName string) *AzureKvProvider {
	return &AzureKvProvider{vaultURL: vaultURL, keyName: keyName}
}

// NewAzureKvProviderWithClient creates a provider with a pre-configured client (for testing).
func NewAzureKvProviderWithClient(keyName string, client AzureWrapKeyAPI) *AzureKvProvider {
	return &AzureKvProvider{keyName: keyName, client: client}
}

func (p *AzureKvProvider) ensureClient() (AzureWrapKeyAPI, error) {
	if p.client != nil {
		return p.client, nil
	}

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	client, err := azkeys.NewClient(p.vaultURL, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure Key Vault client: %w", err)
	}

	p.client = client
	return client, nil
}

func (p *AzureKvProvider) wrapNewKey(ref string) ([]byte, error) {
	client, err := p.ensureClient()
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	alg := azkeys.JSONWebKeyEncryptionAlgorithmRSAOAEP
	_, err = client.WrapKey(context.Background(), p.keyName, "", azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     plaintext,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyNotFound, ref, err)
	}

	return plaintext, nil
}

func (p *AzureKvProvider) Resolve(ref string) (KeyRecord, error) {
	if cached, ok := p.cache.Load(ref); ok {
		return cached.(KeyRecord), nil
	}

	material, err := p.wrapNewKey(ref)
	if err != nil {
		return KeyRecord{}, err
	}

	record := KeyRecord{
		Ref:       ref,
		Version:   1,
		Status:    StatusActive,
		Algorithm: "aes256",
		Material:  material,
		CreatedAt: time.Now(),
	}
	p.cache.Store(ref, record)
	return record, nil
}

func (p *AzureKvProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	if version != 1 {
		return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyNotFound, ref, version)
	}
	return p.Resolve(ref)
}
