package keychain

import "fmt"

// AwsKmsProvider resolves keys using AWS KMS GenerateDataKey.
// Requires: go get github.com/aws/aws-sdk-go-v2/service/kms
type AwsKmsProvider struct {
	keyID    string
	region   string
	endpoint string
}

// NewAwsKmsProvider creates an AWS KMS key provider.
func NewAwsKmsProvider(keyID, region string, endpoint ...string) *AwsKmsProvider {
	ep := ""
	if len(endpoint) > 0 {
		ep = endpoint[0]
	}
	return &AwsKmsProvider{keyID: keyID, region: region, endpoint: ep}
}

func (p *AwsKmsProvider) Resolve(ref string) (KeyRecord, error) {
	return KeyRecord{}, fmt.Errorf("AWS KMS provider not yet implemented — install aws-sdk-go-v2 and wire GenerateDataKey")
}

func (p *AwsKmsProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	return p.Resolve(ref)
}
