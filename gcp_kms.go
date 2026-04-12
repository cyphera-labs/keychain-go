package keychain

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
)

// GcpKmsProvider resolves keys using GCP Cloud KMS.
// Generates a random 32-byte AES key locally, wraps it via KMS Encrypt,
// and caches the plaintext per ref.
type GcpKmsProvider struct {
	keyName string
	client  GcpKmsEncryptAPI
	cache   sync.Map
}

// GcpKmsEncryptAPI is the subset of the GCP KMS client we need, enabling test mocks.
type GcpKmsEncryptAPI interface {
	Encrypt(ctx context.Context, req *kmspb.EncryptRequest, opts ...gax.CallOption) (*kmspb.EncryptResponse, error)
}

// NewGcpKmsProvider creates a GCP Cloud KMS key provider.
// keyName is the fully-qualified KMS key name:
// projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}
func NewGcpKmsProvider(keyName string) *GcpKmsProvider {
	return &GcpKmsProvider{keyName: keyName}
}

// NewGcpKmsProviderWithClient creates a provider with a pre-configured client (for testing).
func NewGcpKmsProviderWithClient(keyName string, client GcpKmsEncryptAPI) *GcpKmsProvider {
	return &GcpKmsProvider{keyName: keyName, client: client}
}

func (p *GcpKmsProvider) ensureClient() (GcpKmsEncryptAPI, error) {
	if p.client != nil {
		return p.client, nil
	}
	ctx := context.Background()
	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCP KMS client: %w", err)
	}
	p.client = client
	return client, nil
}

func (p *GcpKmsProvider) wrapNewKey(ref string) ([]byte, error) {
	client, err := p.ensureClient()
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, 32)
	if _, err := rand.Read(plaintext); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	ctx := context.Background()
	_, err = client.Encrypt(ctx, &kmspb.EncryptRequest{
		Name:                        p.keyName,
		Plaintext:                   plaintext,
		AdditionalAuthenticatedData: []byte(ref),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrKeyNotFound, ref, err)
	}

	return plaintext, nil
}

func (p *GcpKmsProvider) Resolve(ref string) (KeyRecord, error) {
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

func (p *GcpKmsProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	if version != 1 {
		return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyNotFound, ref, version)
	}
	return p.Resolve(ref)
}
