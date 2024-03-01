// Package middleware provides Echo middleware functions for the Grafana Auth Reverse Proxy.
// It includes middleware for logging request information and checking access tokens in requests.
// This package is essential for request processing, ensuring that only authenticated requests are allowed and monitoring request flow.
package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"go.uber.org/zap"
)

// CheckAccessToken creates a middleware function that checks for the presence of an access token in the incoming requests.
// It verifies the token either from the 'Authorization' header or from a cookie. If the token is missing or invalid,
// the request is redirected to the authentication endpoint. Whitelisted paths can bypass this token check.
// Parameters:
// - cfg *config.Config: The configuration object containing settings like endpoints and token cookie name.
// - l *zap.SugaredLogger: A logger for logging debug information.
// Returns:
// - echo.MiddlewareFunc: The middleware function to be used in the Echo server.
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
					extractedToken = cookie.Value
				}
			}

			if extractedToken == "" {
				l.Debugw("Access token cookie missing or invalid", "path", urlPath, "error")
				return c.Redirect(http.StatusFound, cfg.AuthEndpoint)
			}

			return next(c)
		}
	}
}

// Log creates a middleware function that logs the URL of each incoming request.
// This middleware is useful for debugging purposes to track the requests being handled by the server.
// Parameters:
// - l *zap.SugaredLogger: A logger for logging the request URLs.
// Returns:
// - echo.MiddlewareFunc: The middleware function to be used in the Echo server.
func Log(l *zap.SugaredLogger) echo.MiddlewareFunc {
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
