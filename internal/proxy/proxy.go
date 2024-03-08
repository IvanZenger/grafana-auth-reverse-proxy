// Package proxy handles the setup and configuration of the reverse proxy in the Grafana Auth Reverse Proxy application.
// It includes functions to create and configure a reverse proxy that forwards requests to a specified target URL.
// The package is crucial for routing requests to Grafana, handling them based on authentication and authorization rules.
package proxy

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
	"go.uber.org/zap"
)

// Setup configures a reverse proxy in the Echo server to forward requests to a target URL.
// It adjusts the request to point to the target URL and adds necessary headers. The function also
// extracts the access token from the request, validates it, and sets user-related headers before proxying.
// Parameters:
// - e *echo.Echo: The Echo server instance on which the proxy route is to be set up.
// - cfg *config.Config: The configuration object containing the proxy target URL and other settings.
// - l *zap.SugaredLogger: A logger for logging informational messages and errors.
func Setup(e *echo.Echo, cfg *config.Config, l *zap.SugaredLogger) {
	targetURL, err := url.Parse(cfg.ProxyTarget)
	if err != nil {
		l.Errorw("Failed to parse proxy target URL", "error", err)
		return
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	e.Any(path.Join(cfg.BasePath, "/logout"), func(c echo.Context) error {
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

		// Clear the access token cookie
		http.SetCookie(res, &http.Cookie{
			Name:     cfg.AccessTokenCookieName,
			Value:    "",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			Path:     "/",
		})

		proxy.ServeHTTP(res, req)

		return nil
	})

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

		claims, err := jwks.ParseJWTToken(token, cfg.JwksURL)
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

// getTokenFromRequest extracts the JWT token from the given HTTP request.
// It first checks the 'Authorization' header for a 'Bearer' token and falls back to a specified cookie if not found.
// This function is used to retrieve the user's token for further processing or validation.
// Parameters:
// - req *http.Request: The HTTP request from which the token is to be extracted.
// - cookieName: The name of the cookie where the token might be stored.
// Returns:
// - string: The extracted token.
// - error: An error object if the token is not found in either the header or the cookie.
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
