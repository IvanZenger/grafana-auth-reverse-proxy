package proxy

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/auth"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"net/url"
)

func Setup(e *echo.Echo, cfg *config.Config, l *zap.SugaredLogger) {
	targetURL, err := url.Parse(cfg.ProxyTarget)
	if err != nil {
		l.Errorw("Failed to parse proxy target URL", "error", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	e.Any("/*", func(c echo.Context) error {
		fmt.Println("proxy")
		req := c.Request()
		res := c.Response()

		req.URL.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Host = targetURL.Host

		cookie, err := req.Cookie("x-access-token")
		if err != nil {
			l.Debugw("Failed to get cookie", "error", err)
			return c.Redirect(http.StatusFound, "/auth")
		}

		username, err := auth.ExtractTokenUsername(cookie.Value, cfg.JwksUrl)
		if err != nil {
			l.Errorw("Failed to extract username from token", "error", err)
			return echo.NewHTTPError(http.StatusForbidden, "Access denied")
		}

		if username != "" {
			l.Debugw("Extracted username", "username", username)
			req.Header.Set("X-WEBAUTH-USER", username)
		}

		proxy.ServeHTTP(res, req)
		return nil
	})

}
