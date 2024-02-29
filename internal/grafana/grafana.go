package grafana

import (
	"encoding/json"
	"fmt"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
	"go.uber.org/zap"
)

func UpdateUserMapping(idToken string, cfg *config.Config, l *zap.SugaredLogger) error {
	l.Debug("UpdateUserMapping")
	mappings, err := config.LoadOrgMappingConfig(cfg.MappingConfigFile)
	if err != nil {
		return err
	}

	groups, err := ExtractGroupsFromToken(idToken, cfg.OrgAttributePath)
	if err != nil {
		return err
	}

	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksUrl)
	if err != nil {
		return err
	}

	loginOrEmail, err := jwks.ExtractClaimValue(claims, cfg.SyncLoginOrEmailClaimAttribute)
	if err != nil {
		return err
	}

	resolvedMappings := resolveMappings(groups, mappings.OrgMappings)

	l.Debug(resolvedMappings)

	return updateUserOrgRoles(loginOrEmail, cfg.ProxyTarget, resolvedMappings, l)
}

func UpdateRole(idToken string, cfg *config.Config) error {
	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksUrl)
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

	userId, _, err := getUserId(loginOrEmail, cfg.ProxyTarget)
	if err != nil {
		return err
	}

	if result != "" {
		isGrafanaAdmin := false

		if result == "GrafanaAdmin" {
			result = "Admin"
			isGrafanaAdmin = true
		}

		return syncUserRole(cfg.ProxyTarget, loginOrEmail, result.(string), userId, isGrafanaAdmin)
	}

	return err
}
func UpdateUserInfo(idToken string, cfg *config.Config) error {
	claims, err := jwks.ParseJWTToken(idToken, cfg.JwksUrl)
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

	return syncUserInfoWithExternalAuth(cfg.ProxyTarget, loginOrEmail, name, email)
}
