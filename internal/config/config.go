package config

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
)

// Config holds all the configuration for the application
type Config struct {
	CallbackEndpoint      string
	AuthEndpoint          string
	TokenPath             string
	RedirectURL           string
	ClientID              string
	ClientSecret          string
	Issuer                string
	Scopes                []string
	JwksUrl               string
	RedirectGrafanaURL    string
	ProxyTarget           string
	Port                  string
	AccessTokenCookieName string
	OrgAttributePath      string
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
	data, err := ioutil.ReadFile(filename)
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
