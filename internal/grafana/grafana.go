// Package grafana provides functionality to interact with Grafana's API.
// It includes methods for user and organization management within Grafana, such as updating user roles and organization mappings.
// The package plays a key role in ensuring that user information and permissions are correctly synchronized with Grafana.
package grafana

import (
	"encoding/json"
	"fmt"

	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
)

// UpdateUserMapping updates the organization mapping for a user in Grafana based on their ID token.
// It loads the organization mapping configuration, extracts the user's groups from the ID token,
// and resolves these groups into Grafana organization mappings. It then updates the user's organization roles
// in Grafana accordingly.
// Parameters:
// - idToken: The JWT ID token of the user.
// - cfg: Pointer to the Config struct containing configuration settings.
// Returns:
// - error: An error object if any issues occur during the update process.
func UpdateUserMapping(idToken string, cfg *config.Config) error {
	mappings, err := config.LoadOrgMappingConfig(cfg.MappingConfigFile)
	if err != nil {
		return err
	}

	groups, err := ExtractGroupsFromToken(idToken, cfg.OrgAttributePath)
	if err != nil {
		return err
	}

	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksURL)
	if err != nil {
		return err
	}

	loginOrEmail, err := jwks.ExtractClaimValue(claims, cfg.SyncLoginOrEmailClaimAttribute)
	if err != nil {
		return err
	}

	resolvedMappings := resolveMappings(groups, mappings.OrgMappings)

	return updateUserOrgRoles(loginOrEmail, cfg.ProxyTarget, resolvedMappings, cfg)
}

// UpdateRole updates the user's role in Grafana based on their ID token.
// It parses the ID token to extract role information and updates the user's role in Grafana.
// This includes setting the Grafana admin role if applicable.
// Parameters:
// - idToken: The JWT ID token of the user.
// - cfg: Pointer to the Config struct containing configuration settings.
// Returns:
// - error: An error object if any issues occur during the role update process.
func UpdateRole(idToken string, cfg *config.Config) error {
	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksURL)
	if err != nil {
		return err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("error marshaling claims to JSON: %w", err)
	}

	result, err := searchJSONForAttr(cfg.RoleAttributePath, claimsJSON)
	if err != nil {
		return err
	}

	loginOrEmail, err := jwks.ExtractClaimValue(claims, cfg.SyncLoginOrEmailClaimAttribute)
	if err != nil {
		return err
	}

	userID, _, err := getUserID(loginOrEmail, cfg.ProxyTarget, cfg)
	if err != nil {
		return err
	}

	if result != "" {
		isGrafanaAdmin := false

		if result == RoleGrafanaAdmin {
			result = RoleAdmin
			isGrafanaAdmin = true
		}

		return syncUserRole(cfg.ProxyTarget, loginOrEmail, result.(string), userID, isGrafanaAdmin, cfg)
	}

	return err
}

// UpdateUserInfo updates a user's information in Grafana based on their ID token.
// It extracts the user's login or email, name, and email from the ID token and updates
// the user's information in Grafana using external authentication.
// Parameters:
// - idToken: The JWT ID token of the user.
// - cfg: Pointer to the Config struct containing configuration settings.
// Returns:
// - error: An error object if any issues occur during the user info update process.
func UpdateUserInfo(idToken string, cfg *config.Config) error {
	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksURL)
	if err != nil {
		return err
	}

	loginOrEmail, err := jwks.ExtractClaimValue(claims, cfg.SyncLoginOrEmailClaimAttribute)
	if err != nil {
		return err
	}

	name, err := jwks.ExtractClaimValue(claims, cfg.SyncNameClaimAttribute)
	if err != nil {
		return err
	}

	email, err := jwks.ExtractClaimValue(claims, cfg.SyncEmailClaimAttribute)
	if err != nil {
		return err
	}

	return syncUserInfoWithExternalAuth(cfg.ProxyTarget, loginOrEmail, name, email, cfg)
}
