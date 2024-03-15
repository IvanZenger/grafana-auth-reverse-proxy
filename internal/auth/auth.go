// Package auth manages the authentication mechanisms for the Grafana Auth Reverse Proxy.
// It includes functions to set up authentication routes and handle the authentication logic.
// This package interacts with OIDC providers, processes JWT tokens, and ensures that users are correctly authenticated.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/grafana"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/jwks"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/utlis"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// Setup configures the Echo server with routes and handlers for authentication and callback endpoints.
// It defines the GET routes for the callback and authentication endpoints and attaches their respective handlers.
// Parameters:
// - e *echo.Echo: The Echo server instance to set up the routes on.
// - cfg *config.Config: The configuration object containing settings like endpoints.
// - l *zap.SugaredLogger: A logger for logging informational messages and errors.
func Setup(e *echo.Echo, cfg *config.Config, l *zap.SugaredLogger) {
	e.GET(cfg.CallbackEndpoint, func(c echo.Context) error {
		return Callback(c, cfg, l)
	}, echomiddleware.Logger())

	e.GET(cfg.AuthEndpoint, func(c echo.Context) error {
		return Authenticate(c, cfg, l)
	})
}

// Callback handles the OIDC callback endpoint. It performs the token exchange, token verification,
// and updates user information in Grafana based on the obtained token.
// The function also sets a cookie with the access token and redirects to the root URL after a delay.
// Parameters:
// - ctx echo.Context: The Echo context containing request and response data.
// - cfg *config.Config: The configuration object with OIDC and server settings.
// - l *zap.SugaredLogger: A logger for logging errors and informational messages.
// Returns:
// - error: An error object if any issues occur during the callback handling.
func Callback(ctx echo.Context, cfg *config.Config, l *zap.SugaredLogger) error {
	c := context.Background()

	provider, err := oidc.NewProvider(c, cfg.Issuer)
	if err != nil {
		l.Errorw("Failed to get OIDC provider", "error", err)
		return err
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		RedirectURL:  cfg.RedirectURL,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}

	const state = "none"

	oidcConfig := &oidc.Config{
		ClientID: cfg.ClientID,
	}

	verifier := provider.Verifier(oidcConfig)

	if ctx.Request().URL.Query().Get("state") != state {
		l.Errorw("Failed to exchange token", "error", "state did not match")
		return echo.NewHTTPError(http.StatusBadRequest, "state did not match")
	}

	oauth2Token, err := oauth2Config.Exchange(c, ctx.Request().URL.Query().Get("code"))
	if err != nil {
		l.Errorw("Failed to exchange token", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to exchange token: "+err.Error())
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		l.Error("No id_token field in oauth2 token")
		return echo.NewHTTPError(http.StatusInternalServerError, "No id_token field in oauth2 token.")
	}

	idToken, err := verifier.Verify(c, rawIDToken)
	if err != nil {
		l.Errorw("Failed to verify ID Token", "error", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to verify ID Token: "+err.Error())
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err.Error())
	}

	cookie := &http.Cookie{
		Name:     cfg.AccessTokenCookieName,
		Value:    oauth2Token.AccessToken,
		MaxAge:   cfg.AccessTokenMaxAge,
		HttpOnly: true,
		Secure:   cfg.Secure,
		Path:     "/",
	}

	ctx.SetCookie(cookie)

	err = grafana.UpdateUserMapping(rawIDToken, cfg)
	if err != nil {
		l.Errorw("Failed to update User Organization Mapping", "error", err)
	}

	err = grafana.UpdateUserInfo(rawIDToken, cfg)
	if err != nil {
		l.Errorw("Failed to update User Infos", "error", err)
	}

	err = grafana.UpdateRole(rawIDToken, cfg)
	if err != nil {
		l.Errorw("Failed to update User Role", "error", err)
	}

	time.Sleep(time.Second * time.Duration(cfg.SleepBeforeRedirect))

	return ctx.Redirect(302, cfg.RootURL+"/login")
}

// Authenticate initiates the authentication process with the OIDC provider.
// It redirects the user to the OIDC provider's authorization URL, or returns an authenticated response
// if the user already has a valid token.
// Parameters:
// - ctx echo.Context: The Echo context containing request and response data.
// - cfg *config.Config: The configuration object with OIDC and server settings.
// - l *zap.SugaredLogger: A logger for logging errors and informational messages.
// Returns:
// - error: An error object if any issues occur during the authentication process.
func Authenticate(ctx echo.Context, cfg *config.Config, l *zap.SugaredLogger) error {
	l.Debug("Authenticating user")

	c := context.Background()

	provider, err := oidc.NewProvider(c, cfg.Issuer)
	if err != nil {
		l.Errorw("Failed to get OIDC provider", "error", err)
		return err
	}

	if err != nil {
		return err
	}

	oauth2Config := oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       cfg.Scopes,
	}
	state := "none"
	authURL := oauth2Config.AuthCodeURL(state)
	l.Debugw("Redirecting to OIDC provider", "url", authURL)

	jwtTokenString, err := utlis.GetTokenFromRequest(ctx.Request(), cfg.AccessTokenCookieName, l)
	if err != nil {
		l.Debug("could not extract jwtTokenString", err)
		http.Redirect(ctx.Response(), ctx.Request(), oauth2Config.AuthCodeURL(state), http.StatusFound)

		return err
	}

	_, err = jwks.ParseJWTToken(jwtTokenString, cfg.JwksURL)
	if err != nil {
		l.Debug("invalid token", err)
		http.Redirect(ctx.Response(), ctx.Request(), oauth2Config.AuthCodeURL(state), http.StatusFound)

		return err
	}

	l.Debug("is Authenitcated")

	return ctx.JSON(200, "Is Authenticated")
}
