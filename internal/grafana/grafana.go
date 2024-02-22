package grafana

import (
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
)

func UpdateUserMapping(idToken string, cfg *config.Config) error {
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
	return updateUserOrgRoles(loginOrEmail, cfg.ProxyTarget, resolvedMappings)
}
