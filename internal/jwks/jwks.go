// Package jwks contains functions for handling JSON Web Key Sets (JWKS) and parsing JWT tokens.
// It includes utilities for validating JWT tokens against JWKS and extracting specific claim values from these tokens.
// This package is integral to the security aspect of the application, ensuring that JWT tokens are valid and processed correctly.
package jwks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt"
)

// Jwks struct
type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

// JSONWebKeys struct
type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

// ParseJWTToken parses a JWT token string and validates it using the public key obtained from the JWKS (JSON Web Key Set) URL.
// The function extracts the claims from the JWT token upon successful validation.
// Parameters:
// - tokenString: The JWT token string to be parsed and validated.
// - jwksUrl: The URL of the JWKS endpoint to fetch the public key for token validation.
// Returns:
// - jwt.MapClaims: A map of claims extracted from the JWT token if the token is valid.
// - error: An error object if any issues occur during token parsing or validation.
func ParseJWTToken(tokenString, jwksURL string) (jwt.MapClaims, error) {
	var token *jwt.Token
	var err error
	if len(jwksURL) != 0 {
		token, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			cert, err := getPemCertFromJWKS(jwksURL, token)
			if err != nil {
				return nil, err
			}

			publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
			if err != nil {
				return nil, err
			}

			return publicKey, nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		token, _, err = new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
		if err != nil {
			return nil, err
		}
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token or unable to parse claims")
}

// ExtractClaimValue retrieves the value of a specified claim from the given JWT claims map.
// This function is useful for extracting specific information like user ID, email, etc., from JWT tokens.
// Parameters:
// - claims: The JWT claims map from which the value is to be extracted.
// - key: The key of the claim whose value is to be retrieved.
// Returns:
// - string: The value of the specified claim as a string.
// - error: An error object if the claim is not found or if the value is not a string.
func ExtractClaimValue(claims jwt.MapClaims, key string) (string, error) {
	if value, ok := claims[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue, nil
		}

		return "", fmt.Errorf("claim for key '%s' is not a string", key)
	}

	return "", fmt.Errorf("claim for key '%s' not found", key)
}

// getPemCertFromJWKS retrieves the PEM-encoded public key from a JWKS (JSON Web Key Set) endpoint.
// This public key is used for validating JWT tokens. The function matches the 'kid' (Key ID) from the JWT token
// to the corresponding key in the JWKS response.
// Parameters:
// - jwksURL: The URL of the JWKS endpoint.
// - token: The JWT token which contains the 'kid' header used for matching the JWKS key.
// Returns:
// - string: The PEM-encoded public key certificate.
// - error: An error object if any issues occur during fetching or decoding the JWKS, or if the key is not found.
func getPemCertFromJWKS(jwksURL string, token *jwt.Token) (string, error) {
	if _, err := url.ParseRequestURI(jwksURL); err != nil {
		return "", fmt.Errorf("invalid JWKS URL: %w", err)
	}

	client := &http.Client{
		Timeout: time.Second * 10,
	}

	resp, err := client.Get(jwksURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks Jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return "", fmt.Errorf("failed to decode JWKS: %w", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		return "", fmt.Errorf("token 'kid' header is missing or not a string")
	}

	for _, key := range jwks.Keys {
		if key.Kid == kid {
			if len(key.X5c) > 0 {
				return "-----BEGIN CERTIFICATE-----\n" + key.X5c[0] + "\n-----END CERTIFICATE-----", nil
			}

			return "", fmt.Errorf("certificate for 'kid' %s not found in JWKS", kid)
		}
	}

	return "", fmt.Errorf("no matching 'kid' found in JWKS")
}
