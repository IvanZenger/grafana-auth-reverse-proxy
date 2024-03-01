package grafana

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt"
	"github.com/jmespath/go-jmespath"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
)

// ExtractGroupsFromToken extracts group information from the given ID token.
// It utilizes the JMESPath specified in the attributePath parameter to parse the JWT token and extract groups.
// The function is useful for deriving group memberships from JWT claims, typically for access control purposes.
// Parameters:
// - idToken: The JWT token from which the groups need to be extracted.
// - attributePath: The JMESPath expression used to extract the group information from the token.
// Returns:
// - []string: A slice of strings representing the extracted groups.
// - error: An error object if any issues occur during the extraction process.
func ExtractGroupsFromToken(idToken, attributePath string) ([]string, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(idToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("error parsing id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("error asserting claims from id_token")
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("error marshaling claims to JSON: %w", err)
	}

	result, err := searchJSONForAttr(attributePath, claimsJSON)
	if err != nil {
		return nil, err
	}

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

// searchJSONForAttr searches for a specific attribute in the provided JSON data using the JMESPath query language.
// This function is utilized for querying and extracting specific data from a JSON structure.
// Parameters:
// - attributePath: The JMESPath expression used for searching within the JSON data.
// - data: The JSON data in byte slice format to be queried.
// Returns:
// - any: The result of the JMESPath query, which can be of any type depending on the query result.
// - error: An error object if any issues occur during the search process.
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

// resolveMappings resolves organization mappings for the given groups.
// It iterates through the provided mappings and selects those that match any of the groups.
// This function is typically used to map user groups to Grafana organization roles based on predefined mappings.
// Parameters:
// - groups: A slice of strings representing the user's groups.
// - mappings: A slice of OrgMapping objects representing the available organization mappings.
// Returns:
// - []config.OrgMapping: A slice of OrgMapping objects that match the user's groups.
func resolveMappings(groups []string, mappings []config.OrgMapping) []config.OrgMapping {
	var resolvedMappings []config.OrgMapping

	for _, mapping := range mappings {
		if contains(groups, mapping.Group) || mapping.Group == "*" {
			resolvedMappings = append(resolvedMappings, mapping)
		}
	}

	return resolvedMappings
}

// contains checks if a slice of strings contains a specific item.
// It is a helper function used to simplify checks for the presence of a string in a slice.
// Parameters:
// - slice: The slice of strings to be checked.
// - item: The string item to search for in the slice.
// Returns:
// - bool: True if the item is found in the slice, false otherwise.
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}

	return false
}
