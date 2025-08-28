// Package jwt provides ECC-based JWT authentication with deterministic key derivation
package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/OpsMx/oauth-bridge-client/pkg/types"
)

// Service provides ECC JWT operations using a master secret
type Service struct {
	masterSecret string
}

// PrivateKey encapsulates an ECC private key with its metadata and operations
// This prevents direct access to the raw private key material
type PrivateKey struct {
	key    *ecdsa.PrivateKey
	domain string // Domain used for key derivation (replaces orgID)
	kid    string
}

// Signer interface for testing and abstraction
type Signer interface {
	SignJWT(payload *types.ECCJWTPayload) (string, error)
	Domain() string
	Kid() string
	PublicKeyPEM() (string, error)
}

// NewService creates a new ECC JWT service with the provided master secret
func NewService(masterSecret string) *Service {
	return &Service{
		masterSecret: masterSecret,
	}
}

// DeriveKey derives an ECC private key for the given domain and key ID
func (s *Service) DeriveKey(domain, kid string) (*PrivateKey, error) {
	return DeriveKey(s.masterSecret, domain, kid)
}

// ValidateJWT validates a JWT for the given domain and key ID
func (s *Service) ValidateJWT(tokenString, domain, kid string) (*types.ECCJWTPayload, error) {
	return ValidateJWT(tokenString, s.masterSecret, domain, kid)
}

// PrivateKey Methods

// SignJWT signs a JWT using this private key
func (pk *PrivateKey) SignJWT(payload *types.ECCJWTPayload) (string, error) {
	if pk.key == nil {
		return "", fmt.Errorf("private key is nil")
	}
	
	// Validate that payload matches key metadata
	if payload.Issuer != "" {
		issuerDomain := ExtractDomain(payload.Issuer)
		if issuerDomain != pk.domain {
			return "", fmt.Errorf("payload issuer domain (%s) does not match key domain (%s)", issuerDomain, pk.domain)
		}
	}
	if payload.Kid != pk.kid {
		return "", fmt.Errorf("payload kid (%s) does not match key kid (%s)", payload.Kid, pk.kid)
	}
	
	// Set timestamps if not provided
	now := time.Now()
	if payload.IssuedAt == nil {
		payload.IssuedAt = jwt.NewNumericDate(now)
	}
	if payload.ExpiresAt == nil {
		payload.ExpiresAt = jwt.NewNumericDate(now.Add(2 * time.Minute)) // 2 minute expiration
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, payload)
	
	tokenString, err := token.SignedString(pk.key)
	if err != nil {
		return "", fmt.Errorf("failed to sign ECC JWT: %w", err)
	}

	return tokenString, nil
}

// Domain returns the domain associated with this private key
func (pk *PrivateKey) Domain() string {
	return pk.domain
}

// Kid returns the key ID associated with this private key
func (pk *PrivateKey) Kid() string {
	return pk.kid
}

// PublicKeyPEM returns the public key in PEM format
func (pk *PrivateKey) PublicKeyPEM() (string, error) {
	if pk.key == nil {
		return "", fmt.Errorf("private key is nil")
	}
	
	// Marshal public key to PKIX format
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&pk.key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	
	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}
	
	// Encode to PEM format
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

// PrivateKeyPEM returns the private key in PEM format (admin use only)
// WARNING: This exposes the private key material and should only be used for administrative purposes
func (pk *PrivateKey) PrivateKeyPEM() (string, error) {
	if pk.key == nil {
		return "", fmt.Errorf("private key is nil")
	}
	
	// Marshal the private key to ASN.1 DER format
	keyBytes, err := x509.MarshalECPrivateKey(pk.key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	// Create PEM block
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	// Encode to PEM format
	pemBytes := pem.EncodeToMemory(pemBlock)
	return string(pemBytes), nil
}

// Zero securely zeros the private key material and metadata (called by finalizer)
func (pk *PrivateKey) Zero() {
	if pk.key != nil && pk.key.D != nil {
		// Zero out the private key bytes
		pk.key.D.SetInt64(0)
		pk.key = nil
	}
	// Clear sensitive metadata to prevent information leakage
	pk.domain = ""
	pk.kid = ""
}

// Standalone Functions (for external use without service instance)

// DeriveKey derives an ECC private key and returns it as a PrivateKey struct
// This encapsulates the key material and provides secure operations
func DeriveKey(masterSecret, domain, kid string) (*PrivateKey, error) {
	if masterSecret == "" || domain == "" || kid == "" {
		return nil, fmt.Errorf("missing required parameters for key derivation")
	}

	// Create deterministic seed from master secret + domain + kid
	h := hmac.New(sha256.New, []byte(masterSecret))
	h.Write([]byte(domain))
	h.Write([]byte(kid))
	seed := h.Sum(nil)

	// Derive the raw ECC private key
	rawKey, err := DeriveECCKeyFromSeed(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to derive ECC key: %w", err)
	}

	// Create the encapsulated private key
	privateKey := &PrivateKey{
		key:    rawKey,
		domain: domain,
		kid:    kid,
	}

	// Set up finalizer to zero out key material on GC
	runtime.SetFinalizer(privateKey, (*PrivateKey).Zero)

	return privateKey, nil
}

// NewPrivateKey creates a PrivateKey struct from an existing raw ECC private key
// This is used when you already have a parsed private key (e.g., from PEM) and want to encapsulate it
func NewPrivateKey(rawKey *ecdsa.PrivateKey, domain, kid string) *PrivateKey {
	if rawKey == nil {
		return nil
	}
	if domain == "" || kid == "" {
		return nil
	}

	privateKey := &PrivateKey{
		key:    rawKey,
		domain: domain,
		kid:    kid,
	}

	// Set up finalizer to zero out key material on GC
	runtime.SetFinalizer(privateKey, (*PrivateKey).Zero)

	return privateKey
}

// DeriveECCKeyFromSeed derives an ECC private key from a seed using P-256 curve
func DeriveECCKeyFromSeed(seed []byte) (*ecdsa.PrivateKey, error) {
	// Use HMAC-SHA256 to derive a deterministic private key from the seed
	h := hmac.New(sha256.New, seed)
	h.Write([]byte("ecdsa-p256-key-derivation"))
	keyBytes := h.Sum(nil)

	// Ensure the key is within the curve's valid range
	curve := elliptic.P256()
	n := curve.Params().N

	// Create big.Int from the hash
	k := new(big.Int).SetBytes(keyBytes)
	
	// Ensure k is in the valid range [1, n-1]
	one := big.NewInt(1)
	k.Mod(k, new(big.Int).Sub(n, one))
	k.Add(k, one)

	// Create the private key
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: k,
	}

	// Generate the public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(k.Bytes())

	return privateKey, nil
}

// LoadMasterSecret loads the master secret from the configured path
func LoadMasterSecret(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("master secret path not configured")
	}

	secretBytes, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read master secret from %s: %w", path, err)
	}

	// Trim any whitespace/newlines
	return string(secretBytes), nil
}

// ExtractDomain extracts the domain/host from a base URL for key derivation
func ExtractDomain(baseURL string) string {
	if baseURL == "" {
		return ""
	}
	
	// Handle URLs with or without protocol
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	
	parsed, err := url.Parse(baseURL)
	if err != nil {
		// If parsing fails, try to extract manually
		baseURL = strings.TrimPrefix(baseURL, "https://")
		baseURL = strings.TrimPrefix(baseURL, "http://")
		if idx := strings.Index(baseURL, "/"); idx > 0 {
			baseURL = baseURL[:idx]
		}
		return baseURL
	}
	
	return parsed.Host
}

// ValidateJWT validates a JWT signed with ECC (ES256) using deterministic key derivation
func ValidateJWT(tokenString, masterSecret, domain, kid string) (*types.ECCJWTPayload, error) {
	// Parse the token first to extract claims
	token, err := jwt.ParseWithClaims(tokenString, &types.ECCJWTPayload{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method is ES256
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Derive the private key to get the public key for verification
		privateKey, err := DeriveKey(masterSecret, domain, kid)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key for verification: %w", err)
		}

		return &privateKey.key.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract and validate claims
	claims, ok := token.Claims.(*types.ECCJWTPayload)
	if !ok {
		return nil, fmt.Errorf("invalid claims type")
	}

	// Validate required fields
	if claims.Issuer == "" || claims.Kid == "" {
		return nil, fmt.Errorf("missing required JWT fields (issuer or kid)")
	}

	// Validate that the claims match the provided parameters
	issuerDomain := ExtractDomain(claims.Issuer)
	if issuerDomain != domain || claims.Kid != kid {
		return nil, fmt.Errorf("JWT claims do not match provided domain/kid")
	}

	// Additional security checks
	now := time.Now().Unix()

	// Check expiration
	if claims.ExpiresAt != nil && claims.ExpiresAt.Unix() <= now {
		return nil, fmt.Errorf("JWT has expired")
	}

	// Check issued at time (reject tokens from the future)
	if claims.IssuedAt != nil && claims.IssuedAt.Unix() > now+60 { // Allow 1 minute future tolerance
		return nil, fmt.Errorf("JWT issued in the future")
	}

	return claims, nil
}