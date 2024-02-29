package grafana

import (
	"bytes"
	"encoding/json"
	"fmt"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/utlis"
	"net/http"
)

type GrafanaUser struct {
	ID int `json:"id"`
}

type UserOrg struct {
	OrgID int    `json:"orgId"`
	Name  string `json:"name"`
	Role  string `json:"role"`
}

func updateUserOrgRoles(loginOrEmail, host string, resolvedMappings []config.OrgMapping, cfg *config.Config) error {
	userId, statusCode, err := getUserId(loginOrEmail, host, cfg)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		userId, err = createUser(loginOrEmail, host, cfg)
		if err != nil {
			return err
		}
	}

	userOrgs, err := getUserOrgs(userId, host, cfg)
	if err != nil {
		return err
	}

	for _, rm := range resolvedMappings {
		if !orgExists(userOrgs, rm.OrgID) || orgRoleDiffers(userOrgs, rm.OrgID, rm.OrgRole) {
			err := updateUserRoleInOrg(host, userId, rm.OrgID, loginOrEmail, rm.OrgRole, cfg)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getUserId(loginOrEmail, host string, cfg *config.Config) (int, int, error) {
	uri := fmt.Sprintf("/api/users/lookup?loginOrEmail=%s", loginOrEmail)

	resp, err := Request(http.MethodGet, host, uri, true, nil, cfg)
	if err != nil {
		return 0, 0, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return 0, resp.StatusCode, nil
	} else if resp.StatusCode != http.StatusOK {
		return 0, resp.StatusCode, fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var user GrafanaUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return 0, resp.StatusCode, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return user.ID, resp.StatusCode, nil
}

func createUser(loginOrEmail, host string, cfg *config.Config) (int, error) {
	headers := map[string]string{
		cfg.HeaderNameLoginOrEmail: loginOrEmail,
	}

	resp, err := Request(http.MethodGet, host, "/api/users", false, headers, cfg)
	if err != nil {
		return 0, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var user GrafanaUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return 0, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return user.ID, nil
}

func getUserOrgs(userId int, host string, cfg *config.Config) ([]UserOrg, error) {
	uri := fmt.Sprintf("/api/users/%d/orgs", userId)

	resp, err := Request(http.MethodGet, host, uri, true, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("error making request to Grafana: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	var userOrgs []UserOrg
	if err := json.NewDecoder(resp.Body).Decode(&userOrgs); err != nil {
		return nil, fmt.Errorf("error decoding Grafana response: %w", err)
	}

	return userOrgs, nil
}

func updateOrgUser(userId, orgId int, role, host string, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/orgs/%d/users/%d", orgId, userId)

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
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func updateUserRoleInOrg(host string, userId, orgId int, loginOrEmail, newRole string, cfg *config.Config) error {
	userOrgs, err := getUserOrgs(userId, host, cfg)
	if err != nil {
		return fmt.Errorf("error getting user organizations: %w", err)
	}

	if orgExists(userOrgs, orgId) {
		if orgRoleDiffers(userOrgs, orgId, newRole) {
			return updateOrgUser(userId, orgId, newRole, host, cfg)
		}
		return nil
	} else {
		if err := addUserToOrg(orgId, loginOrEmail, newRole, host, cfg); err != nil {
			return fmt.Errorf("error adding user to organization: %w", err)
		}
		return updateOrgUser(userId, orgId, newRole, host, cfg)
	}
}

func addUserToOrg(orgId int, loginOrEmail, role, host string, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/orgs/%d/users", orgId)

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
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func syncUserRole(host, loginOrEmail, role string, userId int, gAdmin bool, cfg *config.Config) error {
	if gAdmin {
		err := syncUserRoleGrafanaAdmin(host, userId, cfg)
		if err != nil {
			return err
		}
	}

	if role != "" {
		err := syncUserRoleWithExternalAuth(host, loginOrEmail, role, cfg)
		if err != nil {
			return err
		}
	}

	return nil
}

func syncUserRoleGrafanaAdmin(host string, userId int, cfg *config.Config) error {
	uri := fmt.Sprintf("/api/admin/users/%d/permissions", userId)

	requestBody, err := json.Marshal(map[string]bool{"isGrafanaAdmin": true})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPut, host, uri, true, requestBody, cfg)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
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
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
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
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func orgExists(orgs []UserOrg, orgId int) bool {
	for _, org := range orgs {
		if org.OrgID == orgId {
			return true
		}
	}
	return false
}
func orgRoleDiffers(orgs []UserOrg, orgId int, role string) bool {
	for _, org := range orgs {
		if org.OrgID == orgId {
			return org.Role != role
		}
	}
	return false
}

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
