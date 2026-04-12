package keychain

import (
	"fmt"
	"os"
)

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
	switch source {
	case "vault":
		addr := firstNonEmpty(config["addr"], os.Getenv("VAULT_ADDR"), "http://127.0.0.1:8200")
		token := firstNonEmpty(config["token"], os.Getenv("VAULT_TOKEN"))
		mount := firstNonEmpty(config["mount"], "secret")
		return NewVaultProvider(addr, token, mount), nil
	case "aws-kms":
		arn := config["arn"]
		region := firstNonEmpty(config["region"], os.Getenv("AWS_REGION"), "us-east-1")
		return NewAwsKmsProvider(arn, region, config["endpoint"]), nil
	case "gcp-kms":
		return NewGcpKmsProvider(config["resource"]), nil
	case "azure-kv":
		vaultURL := fmt.Sprintf("https://%s.vault.azure.net", config["vault"])
		return NewAzureKvProvider(vaultURL, config["key"]), nil
	default:
		return nil, fmt.Errorf("unknown source: %s", source)
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
