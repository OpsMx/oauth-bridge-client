# OAuth Bridge JWT Package

ECC-based JWT utilities for OAuth Bridge authentication with deterministic key derivation.

## Installation

```bash
# Get latest version
go get github.com/OpsMx/oauth-bridge-client/pkg/jwt@latest

# Get specific version
go get github.com/OpsMx/oauth-bridge-client/pkg/jwt@v1.0.0
```

## Usage

```go
import "github.com/OpsMx/oauth-bridge-client/pkg/jwt"
```

## Features

- **Deterministic Key Derivation**: Generate ECC keys from master secrets
- **ECC JWT Signing**: ES256 algorithm support  
- **JWT Validation**: Secure token verification
- **Master Secret Management**: Secure secret loading utilities

## Basic Usage

```go
// Create service with master secret
service := jwt.NewService("your-master-secret")

// Derive private key for organization
privateKey, err := service.DeriveKey("org-id", "key-id")

// Sign JWT payload
payload := &types.ECCJWTPayload{
    Audience: "oauth-bridge",
    OrgID:    "org-id",
    Kid:      "key-id",
}
token, err := service.SignJWT(payload, privateKey)

// Validate JWT
claims, err := service.ValidateJWT(token, "org-id", "key-id")
```

## Standalone Functions

```go
// Direct key derivation
privateKey, err := jwt.DeriveECCKey("master-secret", "org-id", "key-id")

// Direct JWT signing
token, err := jwt.SignECCJWT(payload, privateKey)

// Direct JWT validation  
claims, err := jwt.ValidateECCJWT(token, "master-secret", "org-id", "key-id")
```

## Version Management

This package uses semantic versioning as a Go sub-module:

```bash
# List available versions
git tag --list | grep "pkg/jwt"
```

## Dependencies

- `github.com/golang-jwt/jwt/v5` - JWT handling
- `github.com/OpsMx/oauth-bridge-client/pkg/types` - Payload types
- Standard Go crypto libraries