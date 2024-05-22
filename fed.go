package main

import (
	"context"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type state struct {
	Fingerprint string `json:"fingerprint"`
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
			var providerContext = ctx
			if !config.Federation.OpenIdConnect.ValidateIssuer {
				providerContext = oidc.InsecureIssuerURLContext(providerContext, config.Federation.OpenIdConnect.Issuer)
			}
			oidcProvider, err := oidc.NewProvider(providerContext, config.Federation.OpenIdConnect.Issuer)
			if err != nil {
				return nil, err
			}
			oauth2Config := &oauth2.Config{
				ClientID:     config.Federation.OpenIdConnect.ClientId,
				ClientSecret: config.Federation.OpenIdConnect.ClientSecret,
				RedirectURL:  config.Federation.OpenIdConnect.RedirectUri,

				Endpoint: oidcProvider.Endpoint(),

				Scopes: config.Federation.OpenIdConnect.Scopes,
			}
			if config.Federation.OpenIdConnect.TokenEndpoint != "" {
				oauth2Config.Endpoint.TokenURL = config.Federation.OpenIdConnect.TokenEndpoint
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
