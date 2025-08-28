// Package types defines shared types used across the OAuth bridge application
package types

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)


// ECCJWTPayload represents the JWT payload for ECC-based authentication (new deterministic system)
type ECCJWTPayload struct {
	Issuer    string            `json:"iss"`           // Issuer URL (identifies the SSD service)
	Audience  string            `json:"aud"`           // Audience (OAuth Bridge URL)
	Kid       string            `json:"kid"`           // Key identifier
	ExpiresAt *jwt.NumericDate  `json:"exp,omitempty"` // Expiration timestamp
	IssuedAt  *jwt.NumericDate  `json:"iat,omitempty"` // Issued at timestamp
}

// GetExpirationTime implements jwt.Claims interface
func (p *ECCJWTPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	return p.ExpiresAt, nil
}

// GetIssuedAt implements jwt.Claims interface  
func (p *ECCJWTPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	return p.IssuedAt, nil
}

// GetNotBefore implements jwt.Claims interface
func (p *ECCJWTPayload) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface
func (p *ECCJWTPayload) GetIssuer() (string, error) {
	return "", nil // No issuer for ECC system
}

// GetSubject implements jwt.Claims interface
func (p *ECCJWTPayload) GetSubject() (string, error) {
	return "", nil // No subject for ECC system
}

// GetAudience implements jwt.Claims interface
func (p *ECCJWTPayload) GetAudience() (jwt.ClaimStrings, error) {
	if p.Audience == "" {
		return nil, nil
	}
	return jwt.ClaimStrings{p.Audience}, nil
}

// GitHubJWTPayload represents the JWT payload for GitHub App authentication
type GitHubJWTPayload struct {
	Issuer    string `json:"iss"` // GitHub App ID
	ExpiresAt int64  `json:"exp"` // Expiration timestamp
	IssuedAt  int64  `json:"iat"` // Issued at timestamp
}

// GetExpirationTime implements jwt.Claims interface
func (p *GitHubJWTPayload) GetExpirationTime() (*jwt.NumericDate, error) {
	if p.ExpiresAt == 0 {
		return nil, nil
	}
	t := time.Unix(p.ExpiresAt, 0)
	return jwt.NewNumericDate(t), nil
}

// GetIssuedAt implements jwt.Claims interface
func (p *GitHubJWTPayload) GetIssuedAt() (*jwt.NumericDate, error) {
	if p.IssuedAt == 0 {
		return nil, nil
	}
	t := time.Unix(p.IssuedAt, 0)
	return jwt.NewNumericDate(t), nil
}

// GetNotBefore implements jwt.Claims interface
func (p *GitHubJWTPayload) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetIssuer implements jwt.Claims interface
func (p *GitHubJWTPayload) GetIssuer() (string, error) {
	return p.Issuer, nil
}

// GetSubject implements jwt.Claims interface
func (p *GitHubJWTPayload) GetSubject() (string, error) {
	return "", nil
}

// GetAudience implements jwt.Claims interface
func (p *GitHubJWTPayload) GetAudience() (jwt.ClaimStrings, error) {
	return nil, nil
}

// OAuthState represents the OAuth state parameter for CSRF protection
type OAuthState struct {
	OrgID        string `json:"orgId"`         // Organization identifier
	SessionID    string `json:"sessionId"`     // Unique session ID for cache isolation
	ParentOrigin string `json:"parent_origin"` // Origin for postMessage
	Timestamp    int64  `json:"timestamp"`     // Creation timestamp for expiration
}


// StartInstallationRequest represents the request to start GitHub App installation
type StartInstallationRequest struct {
	Action string `json:"action"`
}

// StartInstallationResponse represents the response to start installation request
type StartInstallationResponse struct {
	Success    bool   `json:"success"`
	InstallURL string `json:"install_url,omitempty"`
	State      string `json:"state,omitempty"`
	Error      string `json:"error,omitempty"`
}

// TokenRequest represents the request to generate an installation access token
type TokenRequest struct {
	Action         string            `json:"action"`
	InstallationID string            `json:"installation_id"`
	Repositories   []string          `json:"repositories,omitempty"`
	Permissions    map[string]string `json:"permissions,omitempty"`
}

// TokenResponse represents the response containing the installation access token
type TokenResponse struct {
	Success     bool              `json:"success"`
	Token       string            `json:"token,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// CallbackData represents data passed to the OAuth callback template
type CallbackData struct {
	Success        bool   `json:"success"`
	InstallationID string `json:"installation_id,omitempty"`
	SSDInstance    string `json:"ssd_instance,omitempty"`
	ParentOrigin   string `json:"parent_origin,omitempty"`
	Error          string `json:"error,omitempty"`
	Timestamp      int64  `json:"timestamp"`
}

// ErrorResponse represents a standard error response
type ErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
}

// InstallationInfo represents GitHub App installation information
type InstallationInfo struct {
	ID           int64             `json:"id"`
	AppID        int64             `json:"app_id"`
	AccountType  string            `json:"account_type"`
	AccountLogin string            `json:"account_login"`
	Permissions  map[string]string `json:"permissions"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// PostMessageData represents the data structure sent via postMessage to parent window
type PostMessageData struct {
	Success        bool   `json:"success"`
	InstallationID string `json:"installation_id,omitempty"`
	SSDInstance    string `json:"ssd_instance,omitempty"`
	Error          string `json:"error,omitempty"`
	Timestamp      int64  `json:"timestamp"`
}

// HealthCheckResponse represents the health check endpoint response
type HealthCheckResponse struct {
	Status    string            `json:"status"`
	Version   string            `json:"version"`
	Timestamp time.Time         `json:"timestamp"`
	Checks    map[string]string `json:"checks,omitempty"`
}

// GenerateKeyRequest represents the request to generate a private key for a domain
type GenerateKeyRequest struct {
	IssuerBaseURL string `json:"issuerBaseUrl"` // Base URL for issuer (e.g., "https://ssd-services.company.com")
	Kid           string `json:"kid"`           // Key identifier
}

// GenerateKeyResponse represents the response containing a generated private key
type GenerateKeyResponse struct {
	Success       bool   `json:"success"`
	PrivateKey    string `json:"privateKey,omitempty"`    // PEM-encoded private key
	Domain        string `json:"domain,omitempty"`        // Extracted domain
	Kid           string `json:"kid,omitempty"`
	IssuerBaseURL string `json:"issuerBaseUrl,omitempty"` // Original issuer base URL
	Error         string `json:"error,omitempty"`
}