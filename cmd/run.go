package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
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

type Run struct {
	CallbackEndpoint string   `env:"CALLBACK_ENDPOINT" default:"/callback"`
	AuthEndpoint     string   `env:"AUTH_ENDPOINT" default:"/auth"`
	TokenPath        string   `env:"TOKEN_PATH" default:"id_token"`
	RedirectURL      string   `env:"REDIRECT_URL" default:"http://localhost:8082/callback"`
	ClientID         string   `env:"CLIENT_ID" default:"grafana"`
	ClientSecret     string   `env:"CLIENT_SECRET" default:"Z7J9KjZUI1LiUDMKKrNCLuewY7DWgDsU"`
	Issuer           string   `env:"ISSUER" default:"http://e1-zengeriv-alsu001:8080/realms/master"`
	Scopes           []string `env:"SCOPES"`

	JwksUrl            string `env:"JWKS_URL" default:"http://e1-zengeriv-alsu001.pnet.ch:8080/realms/master/protocol/openid-connect/certs"`
	RedirectGrafanaURL string `env:"REDIRECT_GRAFANA_URL" default:"http://e1-zengeriv-alsu001:8081/"`
	ProxyTarget        string `env:"PROXY_TARGET" default:"http://e1-zengeriv-alsu001:8081/"`
}

func (r *Run) Run(_ *Globals, l *zap.SugaredLogger) error {
	e := echo.New()

	e.GET(r.CallbackEndpoint, func(c echo.Context) error {
		return Callback(c, *r)
	})

	e.GET(r.AuthEndpoint, func(c echo.Context) error {
		return oauthAuthRedirect(c, *r)
	})

	e.Use(checkAccessToken)

	url, _ := url.Parse(r.ProxyTarget)

	proxy := httputil.NewSingleHostReverseProxy(url)

	e.Any("/*", func(c echo.Context) error {
		fmt.Println("proxy")
		req := c.Request()
		res := c.Response()

		req.URL.Host = url.Host
		req.URL.Scheme = url.Scheme
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Host = url.Host

		cookie, err := req.Cookie("x-access-token")
		if err != nil {
			fmt.Println(err)
		}

		username, err := ExtractTokenUsername(cookie.Value, r.JwksUrl)
		if err != nil {
			fmt.Println(err)
		}

		if username != "" {
			fmt.Println(username)
			req.Header.Set("X-WEBAUTH-USER", username)
		}

		proxy.ServeHTTP(res, req)
		return nil
	})

	e.Logger.Fatal(e.Start(":8082"))

	return nil
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

func checkAccessToken(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		url := c.Request().URL

		whitelistedPaths := []string{"/auth", "/callback"}

		for _, path := range whitelistedPaths {
			if strings.HasPrefix(url.Path, path) {
				return next(c)
			}
		}

		_, err := c.Cookie("x-access-token")
		if err != nil {
			return c.Redirect(302, "/auth")
		}

		return next(c)
	}
}
func handleOAuthCallback(c echo.Context) error {
	// token := c.QueryParam(TokenPath)

	// Redirect the user to Grafana with appropriate headers, cookies, etc.
	// return c.Redirect(http.StatusFound, "http://your-grafana-instance.com")

	// For now, just return a simple confirmation message

	return c.String(http.StatusOK, "OAuth callback handled successfully")
}

func Callback(ctx echo.Context, r Run) error {
	fmt.Println("callback")
	c := context.Background()

	fmt.Println(r.Issuer)
	provider, err := oidc.NewProvider(c, r.Issuer)

	if err != nil {
		fmt.Println(err)
		return err
	}

	r.Scopes = []string{"openid", "email", "roles"}
	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     r.ClientID,
		RedirectURL:  r.RedirectURL,
		ClientSecret: r.ClientSecret,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: r.Scopes,
	}

	const state = "none"

	oidcConfig := &oidc.Config{
		ClientID: r.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)

	/*
		if ctx.Request().URL.Query().Get("state") != state {
			http.Error(ctx.Response(), "state did not match", http.StatusBadRequest)
			return err
		}*/

	//ctxClient := context.WithValue(ctx,oauth2.HTTPClient,	oauth2Config.)

	oauth2Token, err := oauth2Config.Exchange(c, ctx.Request().URL.Query().Get("code"))

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)

	fmt.Println(rawIDToken)

	if !ok {
		return echo.NewHTTPError(http.StatusInternalServerError, "No id_token field in oauth2 token.")
	}

	idToken, err := verifier.Verify(c, rawIDToken)

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	cookie := &http.Cookie{
		Name:     "x-access-token",
		Value:    oauth2Token.AccessToken,
		HttpOnly: true,
		Secure:   true,
		Path:     "/",
	}

	ctx.SetCookie(cookie)

	ctx.Request().Header.Set("X-WEBAUTH-USER", "authenticated-username")

	//redirectToGrafana(ctx, rawIDToken, oauth2Token.AccessToken, r)
	return ctx.Redirect(302, r.RedirectGrafanaURL)
}

func oauthAuthRedirect(ctx echo.Context, r Run) error {
	fmt.Println("auth")
	c := context.Background()
	fmt.Println(r.Issuer)

	provider, err := oidc.NewProvider(c, r.Issuer)

	if err != nil {
		return err
	}

	r.Scopes = []string{"openid", "email", "roles"}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     r.ClientID,
		ClientSecret: r.ClientSecret,
		RedirectURL:  r.RedirectURL,
		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),
		// "openid" is a required scope for OpenID Connect flows.
		Scopes: r.Scopes,
	}
	state := "none"

	http.Redirect(ctx.Response(), ctx.Request(), oauth2Config.AuthCodeURL(state), http.StatusFound)
	return err
}

func redirectToGrafana(c echo.Context, idToken string, accessToken string, r Run) error {
	grafanaOAuthCallbackURL := r.RedirectGrafanaURL
	params := url.Values{}
	params.Add("id_token", idToken)
	params.Add("access_token", accessToken) // Include if neededs

	fullURL := grafanaOAuthCallbackURL + "?" + params.Encode()
	return c.Redirect(http.StatusFound, fullURL)
}
