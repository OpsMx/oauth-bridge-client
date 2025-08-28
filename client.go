// Package oauthbridge provides OAuth Bridge client SDK for SSD services
package oauthbridge

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/OpsMx/oauth-bridge-client/pkg/jwt"
	"github.com/OpsMx/oauth-bridge-client/pkg/types"
)

// Client represents the OAuth Bridge client
type Client struct {
	bridgeURL  string
	issuerURL  string
	kid        string
	privateKey *jwt.PrivateKey
	httpClient *http.Client
}

// NewClient creates a new OAuth Bridge client for the specified service
// It reads infrastructure configuration from environment variables and takes serviceName as a parameter
// If serviceName is empty, the issuer URL will be just the base URL
func NewClient(serviceName string) (*Client, error) {

	// Read configuration from environment variables
	bridgeURL := os.Getenv("OAUTH_BRIDGE_URL")
	if bridgeURL == "" {
		return nil, fmt.Errorf("OAUTH_BRIDGE_URL environment variable is required")
	}
	
	kid := os.Getenv("OAUTH_BRIDGE_KID")
	if kid == "" {
		return nil, fmt.Errorf("OAUTH_BRIDGE_KID environment variable is required")
	}
	
	privateKeyPEM := os.Getenv("OAUTH_BRIDGE_PRIVATE_KEY")
	if privateKeyPEM == "" {
		return nil, fmt.Errorf("OAUTH_BRIDGE_PRIVATE_KEY environment variable is required")
	}
	
	issuerBaseURL := os.Getenv("SSD_ISSUER_BASE_URL")
	if issuerBaseURL == "" {
		return nil, fmt.Errorf("SSD_ISSUER_BASE_URL environment variable is required")
	}

	// Extract domain from issuer base URL for key operations
	domain := jwt.ExtractDomain(issuerBaseURL)
	if domain == "" {
		return nil, fmt.Errorf("failed to extract domain from SSD_ISSUER_BASE_URL")
	}

	// Parse ECC private key from PEM format
	rawKey, err := parseECCPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OAUTH_BRIDGE_PRIVATE_KEY: %w", err)
	}

	// Create encapsulated private key with domain and kid
	privateKey := jwt.NewPrivateKey(rawKey, domain, kid)
	if privateKey == nil {
		return nil, fmt.Errorf("failed to create private key (invalid parameters)")
	}

	// Construct issuer URL: if serviceName is empty, use base URL only
	var issuerURL string
	if serviceName == "" {
		issuerURL = strings.TrimSuffix(issuerBaseURL, "/")
	} else {
		issuerURL = strings.TrimSuffix(issuerBaseURL, "/") + "/" + serviceName
	}

	// Create HTTP client
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &Client{
		bridgeURL:  bridgeURL,
		issuerURL:  issuerURL,
		kid:        kid,
		privateKey: privateKey,
		httpClient: httpClient,
	}, nil
}

// StartInstallation starts the GitHub App installation flow
func (c *Client) StartInstallation() (*StartInstallationResponse, error) {
	// Create JWT for authentication
	jwtToken, err := c.signJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"action": "install",
	}

	// Make HTTP request
	url := fmt.Sprintf("%s/api/v1/github/start", c.bridgeURL)
	resp, err := c.makeAuthenticatedRequest("POST", url, jwtToken, requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var response StartInstallationResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for API errors
	if !response.Success {
		return &response, fmt.Errorf("installation failed: %s", response.Error)
	}

	return &response, nil
}

// GenerateToken creates an installation access token for GitHub API access
// permissions is optional - if not provided, token gets all app permissions
func (c *Client) GenerateToken(installationId string, permissions ...string) (*CreateTokenResponse, error) {
	if installationId == "" {
		return nil, fmt.Errorf("installationId is required")
	}

	// Create JWT for authentication
	jwtToken, err := c.signJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	// Prepare request body
	requestBody := map[string]interface{}{
		"action":          "create_token",
		"installation_id": installationId,
	}

	// Add optional permissions (variadic parameter makes this flexible)
	// Note: Permissions are optional - if not provided, token gets all app permissions
	if len(permissions) > 0 {
		// Convert []string format to map[string]string format expected by server
		permissionMap := make(map[string]string)
		for _, perm := range permissions {
			if parts := strings.Split(perm, ":"); len(parts) == 2 {
				permissionMap[parts[0]] = parts[1]
			}
		}
		if len(permissionMap) > 0 {
			requestBody["permissions"] = permissionMap
		}
	}

	// Make HTTP request
	url := fmt.Sprintf("%s/api/v1/github/token", c.bridgeURL)
	resp, err := c.makeAuthenticatedRequest("POST", url, jwtToken, requestBody)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var response CreateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for API errors
	if !response.Success {
		return &response, fmt.Errorf("token generation failed: %s", response.Error)
	}

	return &response, nil
}

// GetInstallationInfo retrieves information about a GitHub App installation
func (c *Client) GetInstallationInfo(installationId string) (*InstallationInfo, error) {
	if installationId == "" {
		return nil, fmt.Errorf("installationId is required")
	}

	// Create JWT for authentication
	jwtToken, err := c.signJWT()
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT: %w", err)
	}

	// Make HTTP request
	url := fmt.Sprintf("%s/api/v1/github/installation/%s", c.bridgeURL, installationId)
	resp, err := c.makeAuthenticatedRequest("GET", url, jwtToken, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse response
	var response struct {
		Success      bool              `json:"success"`
		Installation *InstallationInfo `json:"installation,omitempty"`
		Error        string            `json:"error,omitempty"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Check for API errors
	if !response.Success {
		return nil, fmt.Errorf("failed to get installation info: %s", response.Error)
	}

	return response.Installation, nil
}

// signJWT creates and signs a JWT with the client's private key
func (c *Client) signJWT() (string, error) {
	// Create JWT payload using issuer URL and audience
	payload := &types.ECCJWTPayload{
		Issuer:   c.issuerURL,  // Full service URL (https://ssd-services.company.com/service-name)
		Audience: c.bridgeURL,  // OAuth Bridge URL
		Kid:      c.privateKey.Kid(),
	}

	// Sign JWT using the encapsulated private key
	return c.privateKey.SignJWT(payload)
}

// makeAuthenticatedRequest makes an HTTP request with JWT authentication
func (c *Client) makeAuthenticatedRequest(method, url, jwtToken string, body interface{}) (*http.Response, error) {
	var bodyReader io.Reader

	// Prepare request body if provided
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewBuffer(jsonBody)
	}

	// Create HTTP request
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	req.Header.Set("User-Agent", "oauth-bridge-client-ecc/1.0")

	// Make request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}

	// Check for HTTP errors
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
	}

	return resp, nil
}

// parseECCPrivateKey parses an ECC private key from PEM format
func parseECCPrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block containing the key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	return privateKey, nil
}