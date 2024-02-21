package jwks

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt"
	"log"
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

func ExtractTokenUsername(tokenString string, jwksUrl string) (string, error) {

	// Parse the token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the alg is what you expect
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		/*cert, err := getPemCertFromJWKS(jwksUrl, token)

		if err != nil {
			fmt.Println(err)
			return "", err
		}

		*/

		cert := "-----BEGIN CERTIFICATE-----\nMIICmzCCAYMCBgGNwU5ZrzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQwMjE5MTIxNzMzWhcNMzQwMjE5MTIxOTEzWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCyjHMvkvvNcZjTLv//zlXIth3tbrH4XeJRzdVEhnLDeFtjZcQ/tph0PdwEHd6zIOWn\nj9M+JL5p78ix4oNm0ZpOZ0/IRzgcFuWmG3FRujb6YJEgNucSvxbjsttR/2mdDudEu09xdXJljxepZoVeHXw/6qRNpfjN4FuBQxsejpthO+3neSZxWqzO/eSpqIJ468g30cj5Ez8lZRTu7d1pN+GtOXLE5vZSOnQrdSEspjLVWKD7Ai0ENHEqzXR7/RvOKc1RN2vRAOvS1UG8n0/ZJQ4GsEgld5pAO0YV5iAXOMzJNnK0NxMsC9Xh\ntTTc5I2vxRdyH1xKclYKeozWjQrRqKRPAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAF/8AJuIvUt6tx47BQJ/eTiOAWOpQJ/rxureISDYEQW/kVLYa/XRdZP3OLgDglmjcuYznPKWYjFSlHu+2BusoxUch3vdgEPHSgUu/0eR3rmk6tq39bspT8DPYNCc5MSFNX62zkIuVnXBBYJFgDNSdnXIUJWyGZrQxcsvf2G/aLtOtQfeSr+z\nCFo0wSIBWnG8N8IacQDNatCucWrnnblSwfRAJNJXs53PIwNCm/LQsnV0aXgU8v2hBvhnF9N+hE2zRZBWc33/11otJt3F27XG8AqX7OS04OYHqzSO54JqmcVoX1X30Zwqsxzw4FEEjMZKTnBxOqkENr6sYuYepvjgKts=\n-----END CERTIFICATE-----\n"

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		return publicKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Use the claims
		log.Println(claims["preferred_username"])
		return claims["preferred_username"].(string), err
	} else {
		fmt.Println("here")
		log.Println(err)

	}
	return "", nil
}

func getPemCertFromJWKS(jwksURL string, token *jwt.Token) (string, error) {
	cert := ""

	resp, err := http.Get(jwksURL) //nolint:gosec //The variable jwksURL can't be a constant because its value depends on the deployment environment.

	if err != nil {
		fmt.Println(err)
		return cert, err
	}

	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		return cert, err
	}

	return cert, nil
}
