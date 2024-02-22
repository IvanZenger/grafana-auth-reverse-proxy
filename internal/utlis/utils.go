package utlis

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

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
func GetTokenFromRequest(req *http.Request, cookieName string) (string, error) {
	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		splitToken := strings.Split(authHeader, "Bearer ")
		if len(splitToken) == 2 {
			return splitToken[1], nil
		}
	} else {
		fmt.Println("Auth Header is empty")
	}

	cookie, err := req.Cookie(cookieName)
	if err == nil {
		return cookie.Value, nil
	}

	return "", fmt.Errorf("no token found")
}
