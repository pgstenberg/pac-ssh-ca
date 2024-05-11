package main

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type State struct {
	Thumbprint string `json:"thumbprint"`
	Principal  string `json:"principal"`
	jwt.RegisteredClaims
}

var fedLock = &sync.Mutex{}

type federation struct {
	oauth2Config        *oauth2.Config
	oidcIDTokenVerifier *oidc.IDTokenVerifier
	oidcProvider        *oidc.Provider
}

var federationInstance *federation

func getFederationInstance(ctx context.Context, config *Config) (*federation, error) {

	if federationInstance == nil {
		fedLock.Lock()
		defer fedLock.Unlock()

		if federationInstance == nil {
			oidcProvider, err := oidc.NewProvider(ctx, config.OpenIdConnect.Issuer)
			if err != nil {
				return nil, err
			}
			oauth2Config := &oauth2.Config{
				ClientID:     config.OpenIdConnect.ClientId,
				ClientSecret: config.OpenIdConnect.ClientSecret,
				RedirectURL:  config.OpenIdConnect.RedirectUri,

				Endpoint: oidcProvider.Endpoint(),

				Scopes: config.OpenIdConnect.Scopes,
			}

			oidcIDTokenVerifier := oidcProvider.Verifier(&oidc.Config{
				ClientID: oauth2Config.ClientID,
			})
			return &federation{
				oauth2Config:        oauth2Config,
				oidcProvider:        oidcProvider,
				oidcIDTokenVerifier: oidcIDTokenVerifier,
			}, nil
		}
	}

	return federationInstance, nil

}
