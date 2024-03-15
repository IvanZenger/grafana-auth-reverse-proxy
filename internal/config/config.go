// Package config defines the configuration structures and loading mechanisms for the Grafana Auth Reverse Proxy.
// It includes definitions for server, token, OIDC, and proxy configurations as well as functions for loading organization mappings.
// The package is essential for managing application settings and providing these configurations throughout the application.
package config

import (
	"os"
	"path/filepath"

	"go.uber.org/zap"
	"gopkg.in/yaml.v2"
)

// Config holds all the configuration settings for the Grafana Auth Reverse Proxy application.
// It includes server details, token information, OIDC provider settings, proxy target configuration,
// and various attributes for Grafana integration. The configuration is used throughout the application
// to initialize and manage different components and their interactions.
type Config struct {
	CallbackEndpoint               string
	AuthEndpoint                   string
	TokenPath                      string
	RedirectURL                    string
	ClientID                       string
	ClientSecret                   string
	Issuer                         string
	Scopes                         []string
	JwksURL                        string
	ProxyTarget                    string
	Port                           string
	Secure                         bool
	RootURL                        string
	SleepBeforeRedirect            int
	BasePath                       string
	AccessTokenCookieName          string
	AccessTokenMaxAge              int
	OrgAttributePath               string
	MappingConfigFile              string
	RoleAttributePath              string
	SyncLoginOrEmailClaimAttribute string
	SyncEmailClaimAttribute        string
	SyncNameClaimAttribute         string
	AdminUser                      string
	HeaderNameLoginOrEmail         string
	HeaderNameName                 string
	HeaderNameEmail                string
	HeaderNameRole                 string
}

// OrgMappingConfig represents the structure of the organization mapping configuration.
// It is used to map groups to Grafana organizations with specific roles.
// The configuration is loaded from a YAML file and used to control access within Grafana.
type OrgMappingConfig struct {
	OrgMappings []OrgMapping `yaml:"org_mapping"`
}

// OrgMapping defines a mapping from a group to a Grafana organization and role.
// Each mapping specifies the group name, the corresponding organization ID in Grafana,
// and the role assigned to users in that organization.
type OrgMapping struct {
	Group   string `yaml:"group"`
	OrgID   int    `yaml:"org_id"`
	OrgRole string `yaml:"org_role"`
}

// LoadOrgMappingConfig reads and parses the organization mapping configuration from the specified YAML file.
// It returns an OrgMappingConfig struct populated with the organization mappings defined in the file.
// Parameters:
// - filename: The name of the file containing the YAML configuration.
// Returns:
// - *OrgMappingConfig: The loaded organization mapping configuration.
// - error: An error object if any issues occur during file reading or parsing.
func LoadOrgMappingConfig(filename string) (*OrgMappingConfig, error) {
	data, err := os.ReadFile(filepath.Clean(filename))
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

// LogConfig logs the current application configuration using the provided logger.
// It outputs detailed configuration settings including server, token, OIDC, proxy, and Grafana specific configurations.
// This method is useful for debugging and verifying the application's configuration at runtime.
// Parameters:
// - l *zap.SugaredLogger: A logger for logging the configuration details.
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
		"AccessTokenMaxAge", cfg.AccessTokenMaxAge,
	)
	l.Infow("OIDC Configuration",
		"ClientID", cfg.ClientID,
		"Issuer", cfg.Issuer,
		"RedirectURL", cfg.RedirectURL,
		"Scopes", cfg.Scopes,
		"JwksURL", cfg.JwksURL,
	)
	l.Infow("Proxy Configuration",
		"ProxyTarget", cfg.ProxyTarget,
	)
	l.Infow("Grafana Configuration",
		"OrgAttributePath", cfg.OrgAttributePath,
		"MappingConfigFile", cfg.MappingConfigFile,
		"RoleAttributePath", cfg.RoleAttributePath,
		"SyncLoginOrEmailClaimAttribute", cfg.SyncLoginOrEmailClaimAttribute,
		"SyncEmailClaimAttribute", cfg.SyncEmailClaimAttribute,
		"SyncNameClaimAttribute", cfg.SyncNameClaimAttribute,
		"AdminUser", cfg.AdminUser,
		"HeaderNameLoginOrEmail", cfg.HeaderNameLoginOrEmail,
		"HeaderNameName", cfg.HeaderNameName,
		"HeaderNameEmail", cfg.HeaderNameEmail,
		"HeaderNameRole", cfg.HeaderNameRole,
	)
}
