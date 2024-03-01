// Package utlis (possibly intended to be 'utils') offers utility functions used across the Grafana Auth Reverse Proxy application.
// It includes common functionalities such as constructing URLs and extracting tokens from HTTP requests.
// This package serves as a helper module, providing shared capabilities that are essential for various operations in the application.
package utlis

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"go.uber.org/zap"
)

// ConstructURL combines a host URL and a URI to form a complete URL.
// It parses and validates the host and URI, then constructs a well-formed URL by joining them.
// This function is particularly useful for constructing URLs from separate components in a consistent manner.
// Parameters:
// - host: The base host URL.
// - uri: The URI to be appended to the host URL.
// Returns:
// - string: The combined URL as a string.
// - error: An error object if either the host or URI is invalid or if there is an error in joining paths.
func ConstructURL(host, uri string) (string, error) {
	hostURL, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("invalid host URL: %w", err)
	}

	uriURL, err := url.Parse(uri)
	if err != nil {
		return "", fmt.Errorf("invalid URI: %w", err)
	}

	completePath, err := url.JoinPath(hostURL.Path, uriURL.Path)
	if err != nil {
		return "", fmt.Errorf("error joining paths: %w", err)
	}

	fullURL := &url.URL{
		Scheme:   hostURL.Scheme,
		Host:     hostURL.Host,
		Path:     completePath,
		RawQuery: uriURL.RawQuery,
		Fragment: uriURL.Fragment,
	}

	return fullURL.String(), nil
}

// GetTokenFromRequest extracts a JWT token from an HTTP request.
// It first checks the 'Authorization' header for a 'Bearer' token and then checks for a cookie if the header is not present.
// This function is used to retrieve the user's authentication token for further processing or validation.
// Parameters:
// - req *http.Request: The HTTP request from which the token is to be extracted.
// - cookieName: The name of the cookie where the token might be stored.
// - l *zap.SugaredLogger: A logger for logging debug information.
// Returns:
// - string: The extracted token.
// - error: An error object if the token is not found in either the header or the cookie.
func GetTokenFromRequest(req *http.Request, cookieName string, l *zap.SugaredLogger) (string, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) == 2 {
			return splitToken[1], nil
		}
	}

	l.Debugw("Auth", "GetTokenFromRequest", "No Token Found in Authorization Header")

	cookie, err := req.Cookie(cookieName)
	if err == nil {
		return cookie.Value, nil
	}

	l.Debugw("Auth", "GetTokenFromRequest", "No Cookie Found in With Token")

	return "", fmt.Errorf("no token found")
}
