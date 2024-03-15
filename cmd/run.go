package cmd

import (
	"fmt"
	"net/url"
	"path"

	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/auth"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/middleware"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/proxy"
	"go.uber.org/zap"
)

// Run struct
type Run struct {
	// Server configuration settings, prefixed with SERVER_ in environment variables.
	Server `envprefix:"SERVER_" help:"Configuration settings related to the server itself, such as endpoints, port, and SSL settings."`

	// TokenConfig configuration settings, prefixed with TOKEN_CONFIG_ in environment variables.
	TokenConfig `envprefix:"TOKEN_CONFIG_" help:"Settings related to token handling, including token path and the name of the cookie used to store the access token."`

	// Oidc configuration settings, prefixed with OIDC_ in environment variables.
	Oidc `envprefix:"OIDC_" help:"OpenID Connect (OIDC) specific settings, including client ID, secret, issuer URL, and JWKS URL."`

	// Proxy configuration settings, prefixed with PROXY_ in environment variables.
	Proxy `envprefix:"PROXY_" help:"Configuration for the reverse proxy, including the target URL for proxying requests."`

	// Grafana's configuration settings, prefixed with GRAFANA_ in environment variables.
	Grafana `envprefix:"GRAFANA_" help:"Settings specific to Grafana, such as admin user, organization attribute path, and role attribute path."`
}

// Server struct
type Server struct {
	CallbackEndpoint    string `env:"CALLBACK_ENDPOINT" help:"Endpoint for OIDC callback. Defaults to '/callback'." default:"/callback"`
	AuthEndpoint        string `env:"AUTH_ENDPOINT" help:"Endpoint for initiating authentication. Defaults to '/auth'." default:"/auth"`
	Port                string `env:"PORT" help:"The port on which the server listens. Defaults to '8082'." default:"8082"`
	Secure              bool   `env:"SECURE" help:"Flag to enable secure cookies. Set to true by default." default:"true"`
	RootURL             string `env:"ROOT_URL" help:"The root URL of the server. Used for callback URL construction." default:"http://e1-zengeriv-alsu001:8082/"`
	SleepBeforeRedirect int    `env:"SLEEP_BEFORE_REDIRECT" help:"Delay (in seconds) before redirecting after authentication. Defaults to '1'." default:"1"`
}

// TokenConfig struct
type TokenConfig struct {
	TokenPath             string `env:"TOKEN_PATH" help:"Path to the token in the authentication response. Defaults to 'id_token'." default:"id_token"`
	AccessTokenCookieName string `env:"ACCESS_TOKEN_COOKIE_NAME" help:"Name of the cookie to store the access token. Defaults to 'x-access-token'." default:"x-access-token"`
}

// Oidc struct
type Oidc struct {
	RedirectURL  string   `env:"REDIRECT_URL" help:"URL to redirect after successful OIDC authentication. Defaults to 'http://localhost:8082/callback'." default:"http://localhost:8082/callback"`
	ClientID     string   `env:"CLIENT_ID" help:"Client ID for OIDC provider. Defaults to 'grafana'." default:"grafana"`
	ClientSecret string   `env:"CLIENT_SECRET" help:"Client Secret for OIDC provider." default:"Z7J9KjZUI1LiUDMKKrNCLuewY7DWgDsU"`
	Issuer       string   `env:"ISSUER" help:"URL of the OIDC issuer. Defaults to 'http://e1-zengeriv-alsu001:8080/realms/master'." default:"http://e1-zengeriv-alsu001:8080/realms/master"`
	Scopes       []string `env:"SCOPES" help:"Scopes requested from OIDC provider. Defaults to 'openid,email,roles,profile'." default:"openid,email,roles,profile"`
	JwksURL      string   `env:"JWKS_URL" help:"URL to the JWKS endpoint for token validation. Defaults to the specified URL." default:""`
}

// Proxy struct
type Proxy struct {
	Target string `env:"TARGET" help:"Target URL for the reverse proxy. Defaults to 'http://e1-zengeriv-alsu001:8081/'." default:"http://e1-zengeriv-alsu001:8081/"`
}

// Grafana struct
type Grafana struct {
	AdminUser                      string `env:"ADMIN_USER" help:"Admin username for Grafana. Defaults to 'admin'." default:"admin"`
	OrgAttributePath               string `env:"ORG_ATTRIBUTE_PATH" help:"Path to the organization attribute in the token. Defaults to 'groups'." default:"groups"`
	MappingConfigFile              string `env:"MAPPING_CONFIG_FILE" help:"Path to the organization mapping configuration file. Defaults to './testdata/mapping.yml'." default:"./testdata/mapping.yml"`
	RoleAttributePath              string `env:"ROLE_ATTRIBUTE_PATH" help:"JMESPath expression for role extraction from token. Defaults to a specified expression." default:"contains(groups[*], 'auth.strong') && 'Admin' || contains(groups[*], 'auth.strong') && 'Editor' || 'Viewer'"`
	SyncLoginOrEmailClaimAttribute string `env:"SYNC_LOGIN_OR_EMAIL_CLAIM_ATTRIBUTE" help:"Claim attribute for syncing login or email. Defaults to 'preferred_username'." default:"preferred_username"`
	SyncEmailClaimAttribute        string `env:"SYNC_EMAIL_CLAIM_ATTRIBUTE" help:"Claim attribute for syncing email. Defaults to 'email'." default:"email"`
	SyncNameClaimAttribute         string `env:"SYNC_NAME_CLAIM_ATTRIBUTE" help:"Claim attribute for syncing name. Defaults to 'name'." default:"name"`
	HeaderNameLoginOrEmail         string `env:"HEADER_NAME_LOGIN_OR_EMAIL" help:"Header name for passing login or email. Defaults to 'X-WEBAUTH-USER'." default:"X-WEBAUTH-USER"`
	HeaderNameName                 string `env:"HEADER_NAME_NAME" help:"Header name for passing the user's name. Defaults to 'X-WEBAUTH-NAME'." default:"X-WEBAUTH-NAME"`
	HeaderNameEmail                string `env:"HEADER_NAME_EMAIL" help:"Header name for passing the user's email. Defaults to 'X-WEBAUTH-EMAIL'." default:"X-WEBAUTH-EMAIL"`
	HeaderNameRole                 string `env:"HEADER_NAME_Role" help:"Header name for passing the user's role. Defaults to 'X-WEBAUTH-ROLE'." default:"X-WEBAUTH-ROLE"`
}

// Run configures and starts the Grafana Auth Reverse Proxy server. It sets up the server with the necessary
// configurations derived from the Run struct, including server, token, OIDC, proxy, and Grafana specific settings.
// The function initializes the Echo framework, configures authentication, logging, token validation, and proxy handling.
// Finally, it starts the server on the specified port.
// Parameters:
// - _ *Globals: Global variables, currently unused in this function.
// - l *zap.SugaredLogger: A logger for logging informational messages and errors.
// Returns:
// - error: An error object if any issues occur during the server setup or while starting the server.
func (r *Run) Run(_ *Globals, l *zap.SugaredLogger) error {
	basePath, err := getBasePath(r.RootURL)
	if err != nil {
		return err
	}

	if basePath != "" {
		r.CallbackEndpoint = path.Join(basePath, r.CallbackEndpoint)
		r.AuthEndpoint = path.Join(basePath, r.AuthEndpoint)
	}

	cfg := config.Config{
		CallbackEndpoint:               r.CallbackEndpoint,
		AuthEndpoint:                   r.AuthEndpoint,
		TokenPath:                      r.TokenPath,
		RedirectURL:                    r.RedirectURL,
		ClientID:                       r.ClientID,
		ClientSecret:                   r.ClientSecret,
		Issuer:                         r.Issuer,
		Scopes:                         r.Scopes,
		JwksURL:                        r.JwksURL,
		ProxyTarget:                    r.Target,
		Port:                           r.Port,
		Secure:                         r.Secure,
		RootURL:                        r.RootURL,
		SleepBeforeRedirect:            r.SleepBeforeRedirect,
		BasePath:                       basePath,
		AccessTokenCookieName:          r.AccessTokenCookieName,
		OrgAttributePath:               r.OrgAttributePath,
		MappingConfigFile:              r.MappingConfigFile,
		RoleAttributePath:              r.RoleAttributePath,
		SyncLoginOrEmailClaimAttribute: r.SyncLoginOrEmailClaimAttribute,
		SyncEmailClaimAttribute:        r.SyncEmailClaimAttribute,
		SyncNameClaimAttribute:         r.SyncNameClaimAttribute,
		AdminUser:                      r.AdminUser,
		HeaderNameLoginOrEmail:         r.HeaderNameLoginOrEmail,
		HeaderNameName:                 r.HeaderNameName,
		HeaderNameEmail:                r.HeaderNameEmail,
		HeaderNameRole:                 r.HeaderNameRole,
	}

	l.Info("Starting Grafana Auth Reverse Proxy")
	cfg.LogConfig(l)

	e := echo.New()

	auth.Setup(e, &cfg, l)

	e.Use(middleware.Log(l))

	e.Use(middleware.CheckAccessToken(&cfg, l))

	proxy.Setup(e, &cfg, l)

	l.Infof("Starting server on port %s", cfg.Port)

	if err := e.Start(":" + cfg.Port); err != nil {
		l.Errorf("Failed to start server: %v", err)
		return err
	}

	return nil
}

// getBasePath parses the given URL and returns its path component, returning an error for invalid URLs.
func getBasePath(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("invalid RootURL: %v", err)
	}

	return parsedURL.Path, err
}
