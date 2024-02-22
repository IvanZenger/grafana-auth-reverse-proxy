package cmd

import (
	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/auth"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/middleware"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/proxy"
	"go.uber.org/zap"
)

type Run struct {
	Server             `envprefix:"SERVER_"`
	TokenConfig        `envprefix:"TOKEN_CONFIG_"`
	Oidc               `envprefix:"OIDC_"`
	Proxy              `envprefix:"PROXY_"`
	Grafana            `envprefix:"GRAFANA_"`
	RedirectGrafanaURL string `env:"REDIRECT_GRAFANA_URL" default:"http://e1-zengeriv-alsu001:8082/"`
}

type Server struct {
	CallbackEndpoint string `env:"CALLBACK_ENDPOINT" default:"/callback"`
	AuthEndpoint     string `env:"AUTH_ENDPOINT" default:"/auth"`
	Port             string `env:"PORT" default:"8082"`
	Secure           bool   `env:"SECURE" default:"true"`
}

type TokenConfig struct {
	TokenPath             string `env:"TOKEN_PATH" default:"id_token"`
	UsernameClaim         string `env:"USERNAME_CLAIM" default:"preferred_username"`
	AccessTokenCookieName string `env:"ACCESS_TOKEN_COOKIE_NAME" default:"x-access-token"`
}

type Oidc struct {
	RedirectURL  string   `env:"REDIRECT_URL" default:"http://localhost:8082/callback"`
	ClientID     string   `env:"CLIENT_ID" default:"grafana"`
	ClientSecret string   `env:"CLIENT_SECRET" default:"Z7J9KjZUI1LiUDMKKrNCLuewY7DWgDsU"`
	Issuer       string   `env:"ISSUER" default:"http://e1-zengeriv-alsu001:8080/realms/master"`
	Scopes       []string `env:"SCOPES"`
	JwksUrl      string   `env:"JWKS_URL" default:"http://e1-zengeriv-alsu001.pnet.ch:8080/realms/master/protocol/openid-connect/certs"`
}

type Proxy struct {
	ProxyTarget string `env:"PROXY_TARGET" default:"http://e1-zengeriv-alsu001:8081/"`
}

type Grafana struct {
	OrgAttributePath  string `env:"ORG_ATTRIBUTE_PATH" default:"groups"`
	MappingConfigFile string `env:"MAPPING_CONFIG_FILE" default:"./testdata/mapping.yml"`
}

func (r *Run) Run(_ *Globals, l *zap.SugaredLogger) error {
	cfg := config.Config{
		CallbackEndpoint:      r.CallbackEndpoint,
		AuthEndpoint:          r.AuthEndpoint,
		TokenPath:             r.TokenPath,
		RedirectURL:           r.RedirectURL,
		ClientID:              r.ClientID,
		ClientSecret:          r.ClientSecret,
		Issuer:                r.Issuer,
		Scopes:                r.Scopes,
		JwksUrl:               r.JwksUrl,
		RedirectGrafanaURL:    r.RedirectGrafanaURL,
		ProxyTarget:           r.ProxyTarget,
		Port:                  r.Port,
		Secure:                r.Secure,
		AccessTokenCookieName: r.AccessTokenCookieName,
		OrgAttributePath:      r.OrgAttributePath,
		MappingConfigFile:     r.MappingConfigFile,
	}

	e := echo.New()

	auth.Setup(e, &cfg, l)

	e.Use(middleware.CheckAccessToken(&cfg, l))

	proxy.Setup(e, &cfg, l)

	l.Infof("Starting server on port %s", cfg.Port)
	if err := e.Start(":" + cfg.Port); err != nil {
		l.Errorf("Failed to start server: %v", err)
		return err
	}

	return nil
}
