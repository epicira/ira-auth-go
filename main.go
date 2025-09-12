package iraauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/epicira/ira-auth-go/pkg/rand"
	"github.com/epicira/ira-auth-go/pkg/sanehttp"

	"github.com/jellydator/ttlcache/v3"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v3"
)

type IraAuthConfig struct {
	AppURL          string `yaml:"app_url"`
	AccessTokenName string `yaml:"access_token_name"`
	ClientID        string `yaml:"client_id"`
	ClientSecret    string `yaml:"client_secret"`
	RedirectURL     string `yaml:"redirect_url"`
	LogoutURL       string `yaml:"logout_url"`
	DisableAuth     bool   `yaml:"disable_auth"`
}

type IraAuth struct {
	IraAuthConfig
	IntrospectURL string
	stateCache    *ttlcache.Cache[string, string]
	oauth2Client  *oauth2.Config
	httpClient    *sanehttp.Client
}

func InitializeIraAuth(configFilePath string) (*IraAuth, error) {
	contents, err := os.ReadFile(configFilePath)
	if err != nil {
		return nil, err
	}

	var config IraAuthConfig
	if err := yaml.Unmarshal(contents, &config); err != nil {
		return nil, err
	}

	cache := ttlcache.New(ttlcache.WithTTL[string, string](30 * time.Second))
	go cache.Start()

	return &IraAuth{
		IraAuthConfig: config,
		IntrospectURL: "https://auth.epicode.in/api/introspect",
		oauth2Client: &oauth2.Config{
			ClientID:     config.ClientID,
			ClientSecret: config.ClientSecret,
			Scopes:       []string{"openid"},
			RedirectURL:  config.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://auth.epicode.in/hydra/oauth2/auth",
				TokenURL: "https://auth.epicode.in/hydra/oauth2/token",
			},
		},
		httpClient: sanehttp.NewClient(10*time.Second, true),
		stateCache: cache,
	}, nil
}

func (ia *IraAuth) GetAuthRedirectURL() string {
	state := rand.String(16)
	url := ia.oauth2Client.AuthCodeURL(state)
	ia.stateCache.Set(state, "", 30*time.Second)
	return url
}

type IraAuthCookies struct {
	TokenCookie *http.Cookie
	IDCookie    *http.Cookie
}

func (ia *IraAuth) HandleCallback(state, code string) (*IraAuthCookies, error) {
	if !ia.stateCache.Has(state) {
		return nil, fmt.Errorf("matching state not found")
	}
	token, err := ia.oauth2Client.Exchange(context.Background(), code)
	if err != nil {
		return nil, err
	}

	cookie := new(http.Cookie)
	cookie.Name = ia.AccessTokenName
	cookie.Value = token.AccessToken
	cookie.SameSite = http.SameSiteLaxMode
	cookie.Path = "/"
	cookie.HttpOnly = true
	cookie.Secure = false
	cookie.MaxAge = 360000

	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("ID token not found")
	}
	idCookie := new(http.Cookie)
	idCookie.Name = fmt.Sprintf("%s_id", ia.AccessTokenName)
	idCookie.Value = idToken
	idCookie.SameSite = http.SameSiteLaxMode
	idCookie.Path = "/"
	idCookie.HttpOnly = true
	idCookie.Secure = false
	idCookie.MaxAge = 360000

	return &IraAuthCookies{
		TokenCookie: cookie,
		IDCookie:    idCookie,
	}, nil
}

type IntrospectResponse struct {
	Active bool `json:"active"`
}

func (ia *IraAuth) Introspect(token string) (bool, error) {
	payload := map[string]string{
		"token": token,
	}
	contents, err := json.Marshal(payload)
	if err != nil {
		return false, err
	}

	resp, err := ia.httpClient.Post(ia.IntrospectURL, map[string]string{}, bytes.NewReader(contents), "application/json", &sanehttp.Options{})
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("received %d status code from introspect endpoint", resp.StatusCode)
	}
	var introspectResponse IntrospectResponse
	if err := json.Unmarshal(resp.Response, &introspectResponse); err != nil {
		return false, err
	}
	return introspectResponse.Active, nil
}
