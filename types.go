// Package oauthbridge defines types for OAuth Bridge client SDK
package oauthbridge

import (
	"fmt"
	"time"

	"github.com/OpsMx/oauth-bridge-client/internal/types"
)

// StartInstallationResponse represents the response from start installation
// Uses a simpler structure for client SDK
type StartInstallationResponse struct {
	Success    bool   `json:"success"`
	InstallURL string `json:"install_url,omitempty"`
	State      string `json:"state,omitempty"`
	Error      string `json:"error,omitempty"`
}

// CreateTokenResponse represents the response containing the installation token
// Client-specific version with simplified error handling
type CreateTokenResponse struct {
	Success     bool              `json:"success"`
	Token       string            `json:"token,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Error       string            `json:"error,omitempty"`
}

// InstallationInfo is an alias to the shared type in internal/types
type InstallationInfo = types.InstallationInfo

// ClientError represents an error from the OAuth Bridge client
type ClientError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

// Error implements the error interface
func (e *ClientError) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Code, e.Message, e.Details)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common error codes
const (
	ErrCodeConfigurationError  = "CONFIGURATION_ERROR"
	ErrCodeJWKSError           = "JWKS_ERROR"
	ErrCodeJWTError            = "JWT_ERROR"
	ErrCodeHTTPError           = "HTTP_ERROR"
	ErrCodeValidationError     = "VALIDATION_ERROR"
	ErrCodeNetworkError        = "NETWORK_ERROR"
	ErrCodeAuthenticationError = "AUTHENTICATION_ERROR"
)

// NewClientError creates a new client error
func NewClientError(code, message string) *ClientError {
	return &ClientError{
		Code:    code,
		Message: message,
	}
}

// NewClientErrorWithDetails creates a new client error with details
func NewClientErrorWithDetails(code, message, details string) *ClientError {
	return &ClientError{
		Code:    code,
		Message: message,
		Details: details,
	}
}

// IsClientError checks if an error is a ClientError
func IsClientError(err error) bool {
	_, ok := err.(*ClientError)
	return ok
}

// GetClientError returns the ClientError if the error is a ClientError
func GetClientError(err error) *ClientError {
	if clientErr, ok := err.(*ClientError); ok {
		return clientErr
	}
	return nil
}