// Package jwt provides ECC-based JWT authentication with deterministic key derivation
// This is a clean, focused implementation supporting only ECC authentication
package jwt

// This package has been restructured for clean architecture:
// - All RSA code has been removed (dead code after ECC migration)
// - OAuth state management moved to pkg/oauth
// - GitHub App JWT generation moved to pkg/github
// - Only ECC JWT operations remain here

// For ECC JWT operations, see ecc.go
// All functionality is now provided by standalone functions:
//   - DeriveECCKey(masterSecret, orgID, kid)
//   - ValidateECCJWT(token, masterSecret, orgID, kid)  
//   - SignECCJWT(payload, privateKey)
//   - LoadMasterSecret(path)

// For service-based usage:
//   - NewService(masterSecret) creates a service instance
//   - service.DeriveKey(orgID, kid)
//   - service.ValidateJWT(token, orgID, kid)
//   - service.SignJWT(payload, privateKey)