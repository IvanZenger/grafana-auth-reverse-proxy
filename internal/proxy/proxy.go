package proxy

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
	"go.uber.org/zap"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
)

func Setup(e *echo.Echo, cfg *config.Config, l *zap.SugaredLogger) {
	targetURL, err := url.Parse(cfg.ProxyTarget)
	if err != nil {
		l.Errorw("Failed to parse proxy target URL", "error", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	e.Any(path.Join(cfg.BasePath, "/*"), func(c echo.Context) error {
		l.Debugw("Proxying request", "method", c.Request().Method, "uri", c.Request().RequestURI)

		req := c.Request()
		res := c.Response()

		req.URL.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Host = targetURL.Host

		proxy.ModifyResponse = func(r *http.Response) error {
			r.Request.Host = r.Request.URL.Host
			return nil
		}

		token, err := getTokenFromRequest(req, cfg.AccessTokenCookieName)
		if err != nil {
			l.Debugw("Failed to get token", "error", err)
			return c.Redirect(http.StatusFound, cfg.AuthEndpoint)
		}

		l.Debug(token)

		claims, err := jwks.ParseJWTToken(token, cfg.JwksUrl)
		if err != nil {
			l.Error("Error parsing token:", err)
		}

		loginOrEmail, err := jwks.ExtractClaimValue(claims, cfg.SyncLoginOrEmailClaimAttribute)
		if err != nil {
			l.Errorw("Failed to extract loginOrEmail from token", "error", err)
			return echo.NewHTTPError(http.StatusForbidden, "Access denied")
		}

		if loginOrEmail != "" {
			l.Debugw("Extracted loginOrEmail", "loginOrEmail", loginOrEmail)
			req.Header.Set(cfg.HeaderNameLoginOrEmail, loginOrEmail)
		}

		proxy.ServeHTTP(res, req)
		return nil
	})
}

func getTokenFromRequest(req *http.Request, cookieName string) (string, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) == 2 {
			return splitToken[1], nil
		}
	}

	cookie, err := req.Cookie(cookieName)
	if err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no token found")
}
