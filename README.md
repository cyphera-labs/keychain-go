# keychain-go

[![CI](https://github.com/cyphera-labs/keychain-go/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/keychain-go/actions/workflows/ci.yml)
[![Security](https://github.com/cyphera-labs/keychain-go/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/keychain-go/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

Key provider for Cyphera — resolve keys from AWS KMS, GCP, Azure Key Vault, HashiCorp Vault, env vars, and files.

```
go get github.com/cyphera-labs/keychain-go
```

## Providers

| Provider | Source | Status |
|----------|--------|--------|
| Memory | — | Working |
| Env | `env` | Working |
| File | `file` | Working |
| HashiCorp Vault | `vault` | Working |
| AWS KMS | `aws-kms` | Scaffolded |
| GCP Cloud KMS | `gcp-kms` | Scaffolded |
| Azure Key Vault | `azure-kv` | Scaffolded |

## Usage with Cyphera SDK

Your code never changes — only the config:

```json
{
  "keys": {
    "my-key": { "source": "vault", "path": "secret/data/my-key" }
  }
}
```

## Status

Alpha. API is unstable.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
