package cmd

import (
	"fmt"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/auth"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/middleware"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/proxy"
	"go.uber.org/zap"
	"net/url"
	"path"
)

type Run struct {
	Server      `envprefix:"SERVER_"`
	TokenConfig `envprefix:"TOKEN_CONFIG_"`
	Oidc        `envprefix:"OIDC_"`
	Proxy       `envprefix:"PROXY_"`
	Grafana     `envprefix:"GRAFANA_"`
}

type Server struct {
	CallbackEndpoint string `env:"CALLBACK_ENDPOINT" default:"/callback"`
	AuthEndpoint     string `env:"AUTH_ENDPOINT" default:"/auth"`
	Port             string `env:"PORT" default:"8082"`
	Secure           bool   `env:"SECURE" default:"true"`
	RootUrl          string `env:"ROOT_URL" default:"http://e1-zengeriv-alsu001:8082/"`
}

type TokenConfig struct {
	TokenPath             string `env:"TOKEN_PATH" default:"id_token"`
	AccessTokenCookieName string `env:"ACCESS_TOKEN_COOKIE_NAME" default:"x-access-token"`
}

type Oidc struct {
	RedirectURL  string   `env:"REDIRECT_URL" default:"http://localhost:8082/callback"`
	ClientID     string   `env:"CLIENT_ID" default:"grafana"`
	ClientSecret string   `env:"CLIENT_SECRET" default:"Z7J9KjZUI1LiUDMKKrNCLuewY7DWgDsU"`
	Issuer       string   `env:"ISSUER" default:"http://e1-zengeriv-alsu001:8080/realms/master"`
	Scopes       []string `env:"SCOPES" default:"openid,email,roles,profile"`
	JwksUrl      string   `env:"JWKS_URL" default:"http://e1-zengeriv-alsu001.pnet.ch:8080/realms/master/protocol/openid-connect/certs"`
}

type Proxy struct {
	Target string `env:"TARGET" default:"http://e1-zengeriv-alsu001:8081/"`
}

type Grafana struct {
	OrgAttributePath               string `env:"ORG_ATTRIBUTE_PATH" default:"groups"`
	MappingConfigFile              string `env:"MAPPING_CONFIG_FILE" default:"./testdata/mapping.yml"`
	RoleAttributePath              string `env:"ROLE_ATTRIBUTE_PATH" default:"contains(groups[*], 'auth.strong') && 'Admin' || contains(groups[*], 'auth.strong') && 'Editor' || 'Viewer'"`
	SyncLoginOrEmailClaimAttribute string `env:"SYNC_LOGIN_OR_EMAIL_CLAIM_ATTRIBUTE" default:"preferred_username"`
	SyncEmailClaimAttribute        string `env:"SYNC_EMAIL_CLAIM_ATTRIBUTE" default:"email"`
	SyncNameClaimAttribute         string `env:"SYNC_NAME_CLAIM_ATTRIBUTE" default:"name"`
}

func (r *Run) Run(_ *Globals, l *zap.SugaredLogger) error {
	basePath, err := getBasePath(r.RootUrl)
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
		JwksUrl:                        r.JwksUrl,
		ProxyTarget:                    r.Target,
		Port:                           r.Port,
		Secure:                         r.Secure,
		RootUrl:                        r.RootUrl,
		BasePath:                       basePath,
		AccessTokenCookieName:          r.AccessTokenCookieName,
		OrgAttributePath:               r.OrgAttributePath,
		MappingConfigFile:              r.MappingConfigFile,
		RoleAttributePath:              r.RoleAttributePath,
		SyncLoginOrEmailClaimAttribute: r.SyncLoginOrEmailClaimAttribute,
		SyncEmailClaimAttribute:        r.SyncEmailClaimAttribute,
		SyncNameClaimAttribute:         r.SyncNameClaimAttribute,
	}

	l.Info("Starting Grafana Auth Reverse Proxy")
	cfg.LogConfig(l)

	e := echo.New()

	auth.Setup(e, &cfg, l)

	e.Use(middleware.Log(&cfg, l))

	e.Use(middleware.CheckAccessToken(&cfg, l))

	e.Use(echomiddleware.CORSWithConfig(echomiddleware.CORSConfig{
		AllowOrigins:                             []string{"*"},
		AllowHeaders:                             []string{"content-type"},
		AllowCredentials:                         true,
		UnsafeWildcardOriginWithAllowCredentials: true,
		ExposeHeaders:                            []string{"content-type"},
	}))

	proxy.Setup(e, &cfg, l)

	l.Infof("Starting server on port %s", cfg.Port)
	if err := e.Start(":" + cfg.Port); err != nil {
		l.Errorf("Failed to start server: %v", err)
		return err
	}

	return nil
}

func getBasePath(u string) (string, error) {
	parsedUrl, err := url.Parse(u)
	if err != nil {
		return "", fmt.Errorf("Invalid RootUrl: %v", err)
	}

	return parsedUrl.Path, err
}
