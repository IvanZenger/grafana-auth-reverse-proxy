package utlis

import (
	"fmt"
	"net/url"
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
