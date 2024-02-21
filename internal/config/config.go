package config

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
}
