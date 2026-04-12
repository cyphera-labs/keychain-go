package keychain

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AwsKmsProvider resolves keys using AWS KMS GenerateDataKey.
// Each resolved ref gets an AES-256 data key generated via the configured
// KMS master key. The plaintext data key is cached in memory per ref.
type AwsKmsProvider struct {
	keyID    string
	region   string
	endpoint string
	client   KmsGenerateDataKeyAPI
	cache    sync.Map
}

// KmsGenerateDataKeyAPI is the subset of the KMS client we need, enabling test mocks.
type KmsGenerateDataKeyAPI interface {
	GenerateDataKey(ctx context.Context, params *kms.GenerateDataKeyInput, optFns ...func(*kms.Options)) (*kms.GenerateDataKeyOutput, error)
}

// NewAwsKmsProvider creates an AWS KMS key provider.
// An optional endpoint override can be passed (useful for LocalStack testing).
func NewAwsKmsProvider(keyID, region string, endpoint ...string) *AwsKmsProvider {
	ep := ""
	if len(endpoint) > 0 {
		ep = endpoint[0]
	}
	return &AwsKmsProvider{keyID: keyID, region: region, endpoint: ep}
}

// NewAwsKmsProviderWithClient creates a provider with a pre-configured KMS client (for testing).
func NewAwsKmsProviderWithClient(keyID string, client KmsGenerateDataKeyAPI) *AwsKmsProvider {
	return &AwsKmsProvider{keyID: keyID, client: client}
}

func (p *AwsKmsProvider) ensureClient() (KmsGenerateDataKeyAPI, error) {
	if p.client != nil {
		return p.client, nil
	}

	ctx := context.Background()
	var opts []func(*config.LoadOptions) error
	if p.region != "" {
		opts = append(opts, config.WithRegion(p.region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	var kmsOpts []func(*kms.Options)
	if p.endpoint != "" {
		kmsOpts = append(kmsOpts, func(o *kms.Options) {
			o.BaseEndpoint = &p.endpoint
		})
	}

	p.client = kms.NewFromConfig(cfg, kmsOpts...)
	return p.client, nil
}

func (p *AwsKmsProvider) generate(ref string) (KeyRecord, error) {
	client, err := p.ensureClient()
	if err != nil {
		return KeyRecord{}, err
	}

	ctx := context.Background()
	spec := types.DataKeySpecAes256
	resp, err := client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   &p.keyID,
		KeySpec: spec,
		EncryptionContext: map[string]string{
			"cyphera:ref": ref,
		},
	})
	if err != nil {
		return KeyRecord{}, fmt.Errorf("%w: %s: %v", ErrKeyNotFound, ref, err)
	}

	return KeyRecord{
		Ref:       ref,
		Version:   1,
		Status:    StatusActive,
		Algorithm: "aes256",
		Material:  resp.Plaintext,
		CreatedAt: time.Now(),
	}, nil
}

func (p *AwsKmsProvider) Resolve(ref string) (KeyRecord, error) {
	if cached, ok := p.cache.Load(ref); ok {
		return cached.(KeyRecord), nil
	}
	record, err := p.generate(ref)
	if err != nil {
		return KeyRecord{}, err
	}
	p.cache.Store(ref, record)
	return record, nil
}

func (p *AwsKmsProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	if version != 1 {
		return KeyRecord{}, fmt.Errorf("%w: %s v%d", ErrKeyNotFound, ref, version)
	}
	return p.Resolve(ref)
}
