package grafana

import (
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
)

func UpdateUserMapping(idToken string, cfg *config.Config) error {
	mappings, err := config.LoadOrgMappingConfig("path/to/your/config.yaml")
	if err != nil {
		return err
	}

	groups, err := ExtractGroupsFromToken(idToken, cfg.OrgAttributePath)
	if err != nil {
		return err
	}

	username, err := jwks.ExtractTokenUsername(idToken, cfg.JwksUrl)
	if err != nil {
		return err
	}

	resolvedMappings := resolveMappings(groups, mappings.OrgMappings)
	return updateUserOrgRoles(username, cfg.ProxyTarget, resolvedMappings)
}
