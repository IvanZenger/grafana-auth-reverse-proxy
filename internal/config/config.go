package config

import (
	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
	"os"
)

// Config holds all the configuration for the application
type Config struct {
	CallbackEndpoint               string
	AuthEndpoint                   string
	TokenPath                      string
	RedirectURL                    string
	ClientID                       string
	ClientSecret                   string
	Issuer                         string
	Scopes                         []string
	JwksUrl                        string
	ProxyTarget                    string
	Port                           string
	Secure                         bool
	RootUrl                        string
	BasePath                       string
	AccessTokenCookieName          string
	OrgAttributePath               string
	MappingConfigFile              string
	SyncLoginOrEmailClaimAttribute string
	SyncEmailClaimAttribute        string
	SyncNameClaimAttribute         string
}

type OrgMappingConfig struct {
	OrgMappings []OrgMapping `yaml:"org_mapping"`
}

type OrgMapping struct {
	Group   string `yaml:"group"`
	OrgID   int    `yaml:"org_id"`
	OrgRole string `yaml:"org_role"`
}

func LoadOrgMappingConfig(filename string) (*OrgMappingConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config OrgMappingConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (cfg *Config) LogConfig(l *zap.SugaredLogger) {
	l.Info("Configuration Details")
	l.Infow("Server Configuration",
		"Port", cfg.Port,
		"CallbackEndpoint", cfg.CallbackEndpoint,
		"AuthEndpoint", cfg.AuthEndpoint,
		"Secure", cfg.Secure,
	)
	l.Infow("Token Configuration",
		"TokenPath", cfg.TokenPath,
		"AccessTokenCookieName", cfg.AccessTokenCookieName,
	)
	l.Infow("OIDC Configuration",
		"ClientID", cfg.ClientID,
		"Issuer", cfg.Issuer,
		"RedirectURL", cfg.RedirectURL,
		"Scopes", cfg.Scopes,
		"JwksUrl", cfg.JwksUrl,
	)
	l.Infow("Proxy Configuration",
		"ProxyTarget", cfg.ProxyTarget,
	)
	l.Infow("Grafana Configuration",
		"OrgAttributePath", cfg.OrgAttributePath,
		"MappingConfigFile", cfg.MappingConfigFile,
		"SyncLoginOrEmailClaimAttribute", cfg.SyncLoginOrEmailClaimAttribute,
		"SyncEmailClaimAttribute", cfg.SyncEmailClaimAttribute,
		"SyncNameClaimAttribute", cfg.SyncNameClaimAttribute,
	)
}
