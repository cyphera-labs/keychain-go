package keychain

import "fmt"

// AzureKvProvider resolves keys using Azure Key Vault.
// Requires: go get github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys
type AzureKvProvider struct {
	vaultURL string
	keyName  string
}

// NewAzureKvProvider creates an Azure Key Vault key provider.
func NewAzureKvProvider(vaultURL, keyName string) *AzureKvProvider {
	return &AzureKvProvider{vaultURL: vaultURL, keyName: keyName}
}

func (p *AzureKvProvider) Resolve(ref string) (KeyRecord, error) {
	return KeyRecord{}, fmt.Errorf("Azure Key Vault provider not yet implemented — install azure-sdk-for-go and wire RSA-OAEP wrapping")
}

func (p *AzureKvProvider) ResolveVersion(ref string, version int) (KeyRecord, error) {
	return p.Resolve(ref)
}
