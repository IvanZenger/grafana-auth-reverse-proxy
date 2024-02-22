package jwks

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"net/http"
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func ParseJWTToken(tokenString, jwksUrl string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		//cert := "-----BEGIN CERTIFICATE-----\nMIICmzCCAYMCBgGNwU5ZrzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwMjE5MTIxNzMzWhcNMzQwMjE5MTIxOTEzWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyjHMvkvvNcZjTLv//zlXIth3tbrH4XeJRzdVEhnLDeFtjZcQ/tph0PdwEHd6zIOWn\nj9M+JL5p78ix4oNm0ZpOZ0/IRzgcFuWmG3FRujb6YJEgNucSvxbjsttR/2mdDudEu09xdXJljxepZoVeHXw/6qRNpfjN4FuBQxsejpthO+3neSZxWqzO/eSpqIJ468g30cj5Ez8lZRTu7d1pN+GtOXLE5vZSOnQrdSEspjLVWKD7Ai0ENHEqzXR7/RvOKc1RN2vRAOvS1UG8n0/ZJQ4GsEgld5pAO0YV5iAXOMzJNnK0NxMsC9Xh\ntTTc5I2vxRdyH1xKclYKeozWjQrRqKRPAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAF/8AJuIvUt6tx47BQJ/eTiOAWOpQJ/rxureISDYEQW/kVLYa/XRdZP3OLgDglmjcuYznPKWYjFSlHu+2BusoxUch3vdgEPHSgUu/0eR3rmk6tq39bspT8DPYNCc5MSFNX62zkIuVnXBBYJFgDNSdnXIUJWyGZrQxcsvf2G/aLtOtQfeSr+z\nCFo0wSIBWnG8N8IacQDNatCucWrnnblSwfRAJNJXs53PIwNCm/LQsnV0aXgU8v2hBvhnF9N+hE2zRZBWc33/11otJt3F27XG8AqX7OS04OYHqzSO54JqmcVoX1X30Zwqsxzw4FEEjMZKTnBxOqkENr6sYuYepvjgKts=\n-----END CERTIFICATE-----\n"

		cert, err := getPemCertFromJWKS(jwksUrl, token)
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

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, fmt.Errorf("invalid token or unable to parse claims")
	}
}

func ExtractClaimValue(claims jwt.MapClaims, key string) (string, error) {
	if value, ok := claims[key]; ok {
		if strValue, ok := value.(string); ok {
			return strValue, nil
		} else {
			return "", fmt.Errorf("claim for key '%s' is not a string", key)
		}
	} else {
		return "", fmt.Errorf("claim for key '%s' not found", key)
	}
}

func getPemCertFromJWKS(jwksURL string, token *jwt.Token) (string, error) {
	resp, err := http.Get(jwksURL)
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
