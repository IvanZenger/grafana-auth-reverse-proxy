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

func updateUserOrgRoles(loginOrEmail, host string, resolvedMappings []config.OrgMapping) error {
	userId, statusCode, err := getUserId(loginOrEmail, host)
	if err != nil {
		return err
	}

	if statusCode == http.StatusNotFound {
		userId, err = createUser(loginOrEmail, host)
		if err != nil {
			return err
		}
	}

	userOrgs, err := getUserOrgs(userId, host)
	if err != nil {
		return err
	}

	for _, rm := range resolvedMappings {
		if !orgExists(userOrgs, rm.OrgID) || orgRoleDiffers(userOrgs, rm.OrgID, rm.OrgRole) {
			err := updateUserRoleInOrg(host, userId, rm.OrgID, loginOrEmail, rm.OrgRole)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getUserId(loginOrEmail, host string) (int, int, error) {
	uri := fmt.Sprintf("/api/users/lookup?loginOrEmail=%s", loginOrEmail)

	resp, err := Request(http.MethodGet, host, uri, "")
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

func createUser(loginOrEmail, host string) (int, error) {
	resp, err := Request(http.MethodGet, host, "/api/users", loginOrEmail)
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

func getUserOrgs(userId int, host string) ([]UserOrg, error) {
	uri := fmt.Sprintf("/api/users/%d/orgs", userId)

	resp, err := Request(http.MethodGet, host, uri, "")
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

func updateOrgUser(userId, orgId int, role, host string) error {
	uri := fmt.Sprintf("/api/orgs/%d/users/%d", orgId, userId)

	requestBody, err := json.Marshal(map[string]string{"role": role})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPatch, host, uri, "", requestBody)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Grafana API returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func updateUserRoleInOrg(host string, userId, orgId int, loginOrEmail, newRole string) error {
	userOrgs, err := getUserOrgs(userId, host)
	if err != nil {
		return fmt.Errorf("error getting user organizations: %w", err)
	}

	if orgExists(userOrgs, orgId) {
		if orgRoleDiffers(userOrgs, orgId, newRole) {
			return updateOrgUser(userId, orgId, newRole, host)
		}
		return nil
	} else {
		if err := addUserToOrg(orgId, loginOrEmail, newRole, host); err != nil {
			return fmt.Errorf("error adding user to organization: %w", err)
		}
		return updateOrgUser(userId, orgId, newRole, host)
	}
}

func addUserToOrg(orgId int, loginOrEmail, role, host string) error {
	uri := fmt.Sprintf("/api/orgs/%d/users", orgId)

	requestBody, err := json.Marshal(map[string]interface{}{
		"loginOrEmail": loginOrEmail,
		"role":         role,
	})
	if err != nil {
		return fmt.Errorf("error marshaling request body: %w", err)
	}

	resp, err := RequestWithBody(http.MethodPost, host, uri, "", requestBody)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
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
	return false // Consider returning true or false based on how you want to handle orgs not found
}
func Request(method, host, uri, authUser string) (*http.Response, error) {
	client := http.Client{}

	url, err := utlis.ConstructURL(host, uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	if authUser == "" {
		req.Header.Add("X-WEBAUTH-USER", "admin")
	} else {
		req.Header.Add("X-WEBAUTH-USER", authUser)
	}

	/*
		req.Header.Add("X-WEBAUTH-USER", "grafana-auth-reverse-proxy")
		req.Header.Add("X-WEBAUTH-ROLE", "GrafanaAdmin")
	*/

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}

func RequestWithBody(method, host, uri, authUser string, requestBody []byte) (*http.Response, error) {
	client := http.Client{}

	url, err := utlis.ConstructURL(host, uri)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	if authUser == "" {
		req.Header.Add("X-WEBAUTH-USER", "admin")
	} else {
		req.Header.Add("X-WEBAUTH-USER", authUser)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}

	return resp, nil
}