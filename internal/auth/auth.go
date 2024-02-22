package auth

import (
	"context"
	"encoding/json"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/labstack/echo/v4"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/config"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/internal/grafana"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"net/http"
)

func Setup(e *echo.Echo, cfg *config.Config, l *zap.SugaredLogger) {
	e.GET(cfg.CallbackEndpoint, func(c echo.Context) error {
		return Callback(c, cfg, l)
	})

	e.GET(cfg.AuthEndpoint, func(c echo.Context) error {
		return Authenticate(c, cfg, l)
	})
}

func Callback(ctx echo.Context, cfg *config.Config, l *zap.SugaredLogger) error {
	c := context.Background()

	provider, err := oidc.NewProvider(c, cfg.Issuer)
	if err != nil {
		l.Errorw("Failed to get OIDC provider", "error", err)
		return err
	}

	cfg.Scopes = []string{"openid", "email", "roles", "profile"}

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
		Name:     "x-access-token",
		Value:    oauth2Token.AccessToken,
		HttpOnly: true,
		Secure:   cfg.Secure,
		Path:     "/",
	}

	ctx.SetCookie(cookie)

	err = grafana.UpdateUserMapping(rawIDToken, cfg)
	if err != nil {
		l.Error(err)
	}

	return ctx.Redirect(302, cfg.RedirectGrafanaURL)
}

func Authenticate(ctx echo.Context, cfg *config.Config, l *zap.SugaredLogger) error {
	l.Info("Authenticating user")
	c := context.Background()

	provider, err := oidc.NewProvider(c, cfg.Issuer)
	if err != nil {
		l.Errorw("Failed to get OIDC provider", "error", err)
		return err
	}

	if err != nil {
		return err
	}

	cfg.Scopes = []string{"openid", "email", "roles", "profile"}

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

	http.Redirect(ctx.Response(), ctx.Request(), oauth2Config.AuthCodeURL(state), http.StatusFound)
	return err
}
