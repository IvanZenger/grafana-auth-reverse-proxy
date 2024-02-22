package middleware

import (
	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"go.uber.org/zap"
	"net/http"
	"strings"
)

func CheckAccessToken(cfg *config.Config, l *zap.SugaredLogger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			urlPath := c.Request().URL.Path

			whitelistedPaths := []string{cfg.AuthEndpoint, cfg.CallbackEndpoint}

			if isWhitelisted(urlPath, whitelistedPaths) {
				return next(c)
			}

			var extractedToken string

			authHeader := c.Request().Header.Get("Authorization")
			if authHeader != "" {
				splitToken := strings.Split(authHeader, "Bearer ")
				if len(splitToken) == 2 {
					extractedToken = splitToken[1]
				}
			}

			if extractedToken == "" {
				cookie, err := c.Cookie(cfg.AccessTokenCookieName)
				if err == nil {
					l.Debugw("Access token cookie missing or invalid", "path", urlPath, "error", err)
					extractedToken = cookie.Value
				}
			}

			if extractedToken == "" {
				return c.Redirect(http.StatusFound, cfg.AuthEndpoint)
			}

			return next(c)
		}
	}
}

func Log(cfg *config.Config, l *zap.SugaredLogger) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			l.Debug(c.Request().URL)
			return next(c)
		}
	}
}

// isWhitelisted checks if a given path is in the list of whitelisted paths
func isWhitelisted(path string, whitelistedPaths []string) bool {
	for _, p := range whitelistedPaths {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}
