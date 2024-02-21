package grafana

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/jmespath/go-jmespath"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
)

// ExtractGroupsFromToken extracts groups from id_token using JMESPath
func ExtractGroupsFromToken(idToken, attributePath string) ([]string, error) {
	// First, parse the JWT token
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing id_token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("error asserting claims from id_token")
	}

	// Convert claims to JSON
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("error marshaling claims to JSON: %w", err)
	}

	// Use searchJSONForAttr to find the attribute
	result, err := searchJSONForAttr(attributePath, claimsJSON)
	if err != nil {
		return nil, err
	}

	// Ensure the result is a slice of strings
	groups, ok := result.([]interface{})
	if !ok {
		return nil, errors.New("extracted data is not a slice of strings")
	}

	var groupStrings []string
	for _, g := range groups {
		if str, ok := g.(string); ok {
			groupStrings = append(groupStrings, str)
		}
	}

	return groupStrings, nil
}

func searchJSONForAttr(attributePath string, data []byte) (any, error) {
	if attributePath == "" {
		return "", errors.New("no attribute path specified")
	}

	if len(data) == 0 {
		return "", errors.New("empty user info JSON response provided")
	}

	var buf any
	if err := json.Unmarshal(data, &buf); err != nil {
		return "", fmt.Errorf("%v: %w", "failed to unmarshal user info JSON response", err)
	}

	val, err := jmespath.Search(attributePath, buf)
	if err != nil {
		return "", fmt.Errorf("failed to search user info JSON response with provided path: %q: %w", attributePath, err)
	}

	return val, nil
}

func resolveMappings(groups []string, mappings []config.OrgMapping) []config.OrgMapping {
	var resolvedMappings []config.OrgMapping
	for _, mapping := range mappings {
		if contains(groups, mapping.Group) {
			resolvedMappings = append(resolvedMappings, mapping)
		}
	}
	return resolvedMappings
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
