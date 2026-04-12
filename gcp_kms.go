package keychain

import "fmt"

// GcpKmsProvider resolves keys using GCP Cloud KMS.
// Requires: go get cloud.google.com/go/kms
type GcpKmsProvider struct {
	keyName string
}

// NewGcpKmsProvider creates a GCP Cloud KMS key provider.
func NewGcpKmsProvider(keyName string) *GcpKmsProvider {
	return &GcpKmsProvider{keyName: keyName}
}

func (p *GcpKmsProvider) Resolve(ref string) (KeyRecord, error) {
	return KeyRecord{}, fmt.Errorf("GCP KMS provider not yet implemented — install cloud.google.com/go/kms and wire encrypt/decrypt")
}

func (p *GcpKmsProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	return p.Resolve(ref)
}
