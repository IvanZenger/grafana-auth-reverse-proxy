package grafana

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/utlis"
)

// User represents a user in Grafana, holding the user's ID.
type User struct {
	ID int `json:"id"`
}

// UserOrg represents an organization to which a user belongs in Grafana,
// including the organization's ID, name, and the user's role within that organization.
type UserOrg struct {
	OrgID int    `json:"orgId"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

// updateUserOrgRoles updates the organization roles for a given user in Grafana.
// It ensures the user exists (or creates one if not), then updates the user's role in each specified organization.
// Parameters:
// - loginOrEmail: The user's login or email to identify the user in Grafana.
// - host: The Grafana server's host address.
// - resolvedMappings: A slice of OrgMapping indicating the desired organization memberships and roles.
// - cfg: Pointer to the application configuration.
// Returns:
// - error: An error object if any issues occur during the update process.
func updateUserOrgRoles(loginOrEmail, host string, resolvedMappings []config.OrgMapping, cfg *config.Config) error {
	userID, statusCode, err := getUserID(loginOrEmail, host, cfg)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		userID, err = createUser(loginOrEmail, host, cfg)
		if err != nil {
			return err
		}
	}

	userOrgs, err := getUserOrgs(userID, host, cfg)
	if err != nil {
		return err
	}

	for _, rm := range resolvedMappings {
		if !orgExists(userOrgs, rm.OrgID) || orgRoleDiffers(userOrgs, rm.OrgID, rm.OrgRole) {
			err := updateUserRoleInOrg(host, userID, rm.OrgID, loginOrEmail, rm.OrgRole, cfg)
			if err != nil {
				return err
			}
		}
	}

	// filter those orgs that are not in resolvedMappings, and remove the user from those orgs
	removedOrgs := []int{}
	for _, userOrg := range userOrgs {
		if !hasAdditionalOrg(resolvedMappings, userOrg.OrgID) {
			continue
		}
		removedOrgs = append(removedOrgs, userOrg.OrgID)
	}

	for _, orgId := range removedOrgs {
		fmt.Printf("User name: %s, Remove user from org %d \n", loginOrEmail, orgId)
		err := deleteOrgUser(userID, orgId, loginOrEmail, host, cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

// hasAdditionalOrg checks if the user has additional organization in Grafana that are not in the resolved mappings.
// Parameters:
// - resolvedMappings: A slice of OrgMapping indicating the desired organization memberships and roles.
// - userOrg: A OrgID representing the organization the user belongs to.
// Returns:
// - bool: A boolean indicating if the user has additional organizations.
func hasAdditionalOrg(resolvedMappings []config.OrgMapping, userOrg int) bool {
	for _, rm := range resolvedMappings {
		if rm.OrgID == userOrg {
			return false
		}
	}

	return true
}

// getUserID retrieves the user ID from Grafana based on the user's login or email.
// It returns the user ID, the HTTP status code from the Grafana API, and an error if the request fails.
// Parameters:
// - loginOrEmail: The login or email of the user.
// - host: The Grafana server's host address.
// - cfg: Pointer to the application configuration.
// Returns:
// - userID: The retrieved user ID.
// - statusCode: The HTTP status code returned by Grafana API.
// - error: An error object if the request fails.
func getUserID(loginOrEmail, host string, cfg *config.Config) (userID, statusCode int, err error) {
	uri := fmt.Sprintf("/api/users/lookup?loginOrEmail=%s", loginOrEmail)

	resp, err := Request(http.MethodGet, host, uri, true, nil, cfg)
	if err != nil {
		return 0, 0, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, resp.StatusCode, nil
	} else if resp.StatusCode != http.StatusOK {
		return 0, resp.StatusCode, fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return 0, resp.StatusCode, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return user.ID, resp.StatusCode, nil
}

// createUser creates a new user in Grafana with the given login or email.
// It returns the new user's ID and an error if the creation process fails.
// Parameters:
// - loginOrEmail: The login or email to create the new user with.
// - host: The Grafana server's host address.
// - cfg: Pointer to the application configuration.
// Returns:
// - int: The ID of the newly created user.
// - error: An error object if the user creation fails.
func createUser(loginOrEmail, host string, cfg *config.Config) (int, error) {
	headers := map[string]string{
		cfg.HeaderNameLoginOrEmail: loginOrEmail,
	}

	// https://grafana.com/docs/grafana/latest/setup-grafana/configure-security/configure-authentication/auth-proxy/#interacting-with-grafanas-authproxy-via-curl
	resp, err := Request(http.MethodGet, host, "/api/user", false, headers, cfg)
	if err != nil {
		return 0, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var user User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return 0, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return user.ID, nil
}

// getUserOrgs retrieves a list of organizations that the user with the given ID belongs to in Grafana.
// It returns a slice of UserOrg and an error if the request fails.
// Parameters:
// - userID: The ID of the user to retrieve organizations for.
// - host: The Grafana server's host address.
// - cfg: Pointer to the application configuration.
// Returns:
// - []UserOrg: A slice of UserOrg representing the organizations the user belongs to.
// - error: An error object if the request fails.
func getUserOrgs(userID int, host string, cfg *config.Config) ([]UserOrg, error) {
	uri := fmt.Sprintf("/api/users/%d/orgs", userID)

	resp, err := Request(http.MethodGet, host, uri, true, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var userOrgs []UserOrg
	if err := json.NewDecoder(resp.Body).Decode(&userOrgs); err != nil {
		return nil, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return userOrgs, nil
}

func updateOrgUser(userID, orgID int, role, host string, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/orgs/%d/users/%d", orgID, userID)

	requestBody, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPatch, host, uri, true, requestBody, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func deleteOrgUser(userID, orgID int, _, host string, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/orgs/%d/users/%d", orgID, userID)

	resp, err := RequestWithBody(http.MethodDelete, host, uri, true, []byte{}, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func updateUserRoleInOrg(host string, userID, orgID int, loginOrEmail, newRole string, cfg *config.Config) error {
	userOrgs, err := getUserOrgs(userID, host, cfg)
	if err != nil {
		return fmt.Errorf("error getting user organizations: %w", err)
	}

	if orgExists(userOrgs, orgID) {
		if orgRoleDiffers(userOrgs, orgID, newRole) {
			return updateOrgUser(userID, orgID, newRole, host, cfg)
		}

		return nil
	}

	if err := addUserToOrg(orgID, loginOrEmail, newRole, host, cfg); err != nil {
		return fmt.Errorf("error adding user to organization: %w", err)
	}

	return updateOrgUser(userID, orgID, newRole, host, cfg)
}

func addUserToOrg(orgID int, loginOrEmail, role, host string, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/orgs/%d/users", orgID)

	requestBody, err := json.Marshal(map[string]interface{}{
		"loginOrEmail": loginOrEmail,
		"role":         role,
	})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPost, host, uri, true, requestBody, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func syncUserRole(host, loginOrEmail, role string, userID int, gAdmin bool, cfg *config.Config) error {
	err := syncUserRoleGrafanaAdmin(host, userID, gAdmin, cfg)
	if err != nil {
		return err
	}

	if role != "" {
		err := syncUserRoleWithExternalAuth(host, loginOrEmail, role, cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncUserRoleGrafanaAdmin(host string, userID int, gAdmin bool, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/admin/users/%d/permissions", userID)

	requestBody, err := json.Marshal(map[string]bool{"isGrafanaAdmin": gAdmin})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPut, host, uri, true, requestBody, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}
func syncUserRoleWithExternalAuth(host, loginOrEmail, role string, cfg *config.Config) error {
	headers := map[string]string{
		cfg.HeaderNameRole:         role,
		cfg.HeaderNameLoginOrEmail: loginOrEmail,
	}

	resp, err := Request(http.MethodGet, host, "/api/user", false, headers, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func syncUserInfoWithExternalAuth(host, loginOrEmail, name, email string, cfg *config.Config) error {
	headers := map[string]string{
		cfg.HeaderNameName:         name,
		cfg.HeaderNameEmail:        email,
		cfg.HeaderNameLoginOrEmail: loginOrEmail,
	}

	resp, err := Request(http.MethodGet, host, "/api/user", false, headers, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func orgExists(orgs []UserOrg, orgID int) bool {
	for _, org := range orgs {
		if org.OrgID == orgID {
			return true
		}
	}

	return false
}
func orgRoleDiffers(orgs []UserOrg, orgID int, role string) bool {
	for _, org := range orgs {
		if org.OrgID == orgID {
			return org.Role != role
		}
	}

	return false
}

// Request makes an HTTP request to the Grafana API with the specified method, host, and URI.
// It includes optional additional headers and authentication depending on the 'useAdmin' parameter.
// Parameters:
// - method: The HTTP method for the request (e.g., GET, POST, PUT, DELETE).
// - host: The host address of the Grafana server.
// - uri: The URI path for the API endpoint.
// - useAdmin: A boolean indicating whether to use admin authentication headers.
// - extraHeaders: A map of additional headers to include in the request.
// - cfg: Pointer to the application configuration.
// Returns:
// - *http.Response: A pointer to the HTTP response object.
// - error: An error object if the request fails.
func Request(method, host, uri string, useAdmin bool, extraHeaders map[string]string, cfg *config.Config) (*http.Response, error) {
	client := http.Client{}

	url, err := utlis.ConstructURL(host, uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	if useAdmin {
		req.Header.Add(cfg.HeaderNameLoginOrEmail, cfg.AdminUser)
	}

	for key, value := range extraHeaders {
		req.Header.Add(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}

// RequestWithBody makes an HTTP request to the Grafana API with a request body.
// It includes the specified method, host, URI, request body, and optional additional headers and authentication.
// Parameters:
// - method: The HTTP method for the request (e.g., POST, PUT, PATCH).
// - host: The host address of the Grafana server.
// - uri: The URI path for the API endpoint.
// - useAdmin: A boolean indicating whether to use admin authentication headers.
// - requestBody: The request body data to be sent with the request.
// - cfg: Pointer to the application configuration.
// Returns:
// - *http.Response: A pointer to the HTTP response object.
// - error: An error object if the request fails.
func RequestWithBody(method, host, uri string, useAdmin bool, requestBody []byte, cfg *config.Config) (*http.Response, error) {
	client := http.Client{}

	url, err := utlis.ConstructURL(host, uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	if useAdmin {
		req.Header.Add(cfg.HeaderNameLoginOrEmail, cfg.AdminUser)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}
