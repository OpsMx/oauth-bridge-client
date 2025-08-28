// Package main demonstrates how to use the OAuth Bridge client SDK with ECC authentication
package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/OpsMx/oauth-bridge-client"
)

func main() {
	fmt.Println("OAuth Bridge Client SDK Example (ECC Authentication)")
	fmt.Println("===================================================")

	// Get serviceName from environment (this comes from deployment config)
	// serviceName is now optional - if empty, the issuer URL will be just the base URL
	serviceName := os.Getenv("SSD_SERVICE_NAME")
	if serviceName == "" {
		fmt.Println("WARNING: SSD_SERVICE_NAME not set - using base URL as issuer")
	}

	// Initialize client from environment variables
	// Reads OAUTH_BRIDGE_URL, OAUTH_BRIDGE_KID, OAUTH_BRIDGE_PRIVATE_KEY, SSD_ISSUER_BASE_URL
	// serviceName can be empty string - issuer URL will be just the base URL
	bridgeClient, err := oauthbridge.NewClient(serviceName)
	if err != nil {
		log.Fatalf("Failed to initialize OAuth Bridge client: %v", err)
	}

	// Example 1: Start GitHub App Installation
	fmt.Println("\n1. Starting GitHub App Installation...")
	// Note: Permissions are predefined in GitHub App configuration, not specified here

	startResp, err := bridgeClient.StartInstallation()
	if err != nil {
		log.Fatalf("Failed to start installation: %v", err)
	}

	if !startResp.Success {
		log.Fatalf("Start installation failed: %s", startResp.Error)
	}

	fmt.Printf("Installation URL: %s\n", startResp.InstallURL)
	fmt.Printf("State: %s\n", startResp.State)
	fmt.Println("User should open the URL above to complete GitHub App installation")

	// Example 2: Create Installation Token (after user completes installation)
	fmt.Println("\n2. Creating Installation Token...")

	// In a real scenario, you would get the installation_id from the OAuth callback
	// For this example, we'll use a placeholder
	installationID := os.Getenv("GITHUB_INSTALLATION_ID")
	if installationID == "" {
		fmt.Println("WARNING: Set GITHUB_INSTALLATION_ID environment variable to test token creation")
		fmt.Println("   You can get this from the GitHub App installation callback")
		return
	}

	// Generate token with specific permissions (variadic)
	tokenResp, err := bridgeClient.GenerateToken(installationID, "contents:read", "pull_requests:write", "issues:read")
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	if !tokenResp.Success {
		log.Fatalf("Token creation failed: %s", tokenResp.Error)
	}

	fmt.Printf("Token created successfully\n")
	fmt.Printf("Token: %s...\n", tokenResp.Token[:20])
	fmt.Printf("Expires at: %s\n", tokenResp.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Permissions: %+v\n", tokenResp.Permissions)

	// Example 3: Get Installation Info
	fmt.Println("\n3. Getting Installation Info...")

	installInfo, err := bridgeClient.GetInstallationInfo(installationID)
	if err != nil {
		log.Fatalf("Failed to get installation info: %v", err)
	}

	fmt.Printf("Installation info retrieved\n")
	fmt.Printf("Installation ID: %d\n", installInfo.ID)
	fmt.Printf("App ID: %d\n", installInfo.AppID)
	fmt.Printf("Account: %s (%s)\n", installInfo.AccountLogin, installInfo.AccountType)
	fmt.Printf("Permissions: %+v\n", installInfo.Permissions)
	fmt.Printf("Created: %s\n", installInfo.CreatedAt.Format(time.RFC3339))

	fmt.Println("\nOAuth Bridge client SDK example completed successfully!")
	fmt.Println("\nNote: This example uses domain-based ECC key derivation")
	fmt.Printf("Service: %s\n", serviceName)
	fmt.Println("Private key loaded from OAUTH_BRIDGE_PRIVATE_KEY environment variable")
	fmt.Println("Issuer URL constructed from SSD_ISSUER_BASE_URL + service name")
}