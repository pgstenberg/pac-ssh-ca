package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	sshserver "github.com/gliderlabs/ssh"
	jwt "github.com/golang-jwt/jwt/v5"
	"goji.io"
	"goji.io/pat"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"gopkg.in/yaml.v2"
)

// Config struct for webapp config
type Config struct {
	OpenIdConnect struct {
		Issuer       string   `yaml:"issuer"`
		ClientId     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		RedirectUri  string   `yaml:"redirect_uri"`
		Scopes       []string `yaml:"scopes"`
	} `yaml:"openid_connect"`
}

func NewConfig(configFile string) (*Config, error) {

	config := &Config{}

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	d := yaml.NewDecoder(file)

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}

func main() {

	var configFile string
	var authzmoduleFile string
	var privatekeyFile string
	flag.StringVar(&configFile, "config", "./config.yaml", "path to config file")
	flag.StringVar(&authzmoduleFile, "authzmodule", "./default.rego", "path to opa rego module file")
	flag.StringVar(&privatekeyFile, "privatekey", "./ca", "path ca private key")

	// Actually parse the flags
	flag.Parse()

	config, err := NewConfig(configFile)
	if err != nil {
		log.Fatal("Unable to load configuration: ", configFile)
	}

	ctx := context.TODO()

	policyEngine, err := NewOpenPolicyAgentEngine(authzmoduleFile, ctx)
	if err != nil {
		log.Fatal("Unable to load policy engine: ", err)
	}

	/**
		INIT SSH CERT SIGNER
	**/
	privateBytes, err := os.ReadFile(privatekeyFile)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}
	privateKey, err := ssh.ParseRawPrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}
	publicKey := &(privateKey.(*rsa.PrivateKey)).PublicKey

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	provider, err := oidc.NewProvider(ctx, config.OpenIdConnect.Issuer)
	if err != nil {
		panic(err)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oauth2Config := oauth2.Config{
		ClientID:     config.OpenIdConnect.ClientId,
		ClientSecret: config.OpenIdConnect.ClientSecret,
		RedirectURL:  config.OpenIdConnect.RedirectUri,

		// Discovery returns the OAuth2 endpoints.
		Endpoint: provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: config.OpenIdConnect.Scopes,
	}

	oidcVerifier := provider.Verifier(&oidc.Config{
		ClientID: oauth2Config.ClientID,
	})

	handleOAuth2Callback := func(w http.ResponseWriter, r *http.Request) {

		state := r.URL.Query().Get("state")

		st, err := jwt.ParseWithClaims(state, &StateClaims{}, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			log.Printf("state jwt validation failed: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		stateClaims, ok := st.Claims.(*StateClaims)
		if !ok {
			log.Printf("unable to typecast stateclaims")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		oauth2Token, err := oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			log.Printf("unable to exchange code: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		idToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Printf("no id_token found in token response")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		scope := strings.Join(oauth2Config.Scopes, " ")
		if oauth2Token.Extra("scope") != nil {
			scope = oauth2Token.Extra("scope").(string)
		}

		if _, err := oidcVerifier.Verify(r.Context(), idToken); err != nil {
			log.Printf("id_token verification failed.")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		claims := jwt.MapClaims{}
		inrec, err := json.Marshal(TicketClaims{
			IdToken:     idToken,
			Scope:       scope,
			StateClaims: *stateClaims,
		})
		if err != nil {
			log.Printf("fail during jwt creation")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		if err := json.Unmarshal(inrec, &claims); err != nil {
			log.Printf("fail during jwt creation")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		s, err := t.SignedString(privateKey)
		if err != nil {
			log.Printf("unable to sign jwt: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		io.WriteString(w, s)
	}

	handleSshSession := func(s sshserver.Session) {

		ticket := s.RawCommand()

		if ticket != "" {

			/**
				PARSE TICKET
			**/
			st, err := jwt.ParseWithClaims(ticket, &TicketClaims{}, func(token *jwt.Token) (interface{}, error) {
				return publicKey, nil
			})
			if err != nil {
				log.Printf("jwt verify failed, err: %s", err)
				s.Exit(5)
				return
			}
			ticketClaims, ok := st.Claims.(*TicketClaims)
			if !ok {
				log.Printf("unable to parse claims")
				s.Exit(5)
				return
			}

			/**
				POLICTY EVALUATION
			**/

			result, err := policyEngine.Authorize(s.Context(), &AuthorizationInput{
				Principal:    s.User(),
				ThumbPrint:   ssh.FingerprintSHA256(s.PublicKey()),
				TicketClaims: *ticketClaims,
			})
			if err != nil {
				log.Printf("policy evaluation failed, err: %s", err)
				s.Exit(5)
				return
			}

			permissions := ssh.Permissions{
				CriticalOptions: result.CriticalOptions,
				Extensions:      result.Extensions,
			}

			cert := &ssh.Certificate{
				CertType:        ssh.UserCert,
				Key:             s.PublicKey(),
				ValidPrincipals: result.ValidPrincipals,
				Permissions:     permissions,
				ValidAfter:      result.ValidAfter,
				ValidBefore:     result.ValidBefore,
			}

			if err := cert.SignCert(rand.Reader, signer); err != nil {
				log.Printf("failed to sign certificate; %s", err)
				s.Exit(4)
			}

			io.WriteString(s, string(ssh.MarshalAuthorizedKey(cert)))
			s.Close()
		}

		/**
			NEW AUTHORIZATION REQUEST
		**/

		claims := jwt.MapClaims{}
		inrec, err := json.Marshal(StateClaims{
			Principal:  s.User(),
			ThumbPrint: ssh.FingerprintSHA256(s.PublicKey()),
		})
		if err != nil {
			log.Printf("failed during jwt creation; %s", err)
			s.Exit(5)
		}
		if err := json.Unmarshal(inrec, &claims); err != nil {
			if err != nil {
				log.Printf("failed during jwt creation; %s", err)
				s.Exit(5)
			}
		}

		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		state, err := t.SignedString(privateKey)
		if err != nil {
			log.Printf("failed during jwt signing; %s", err)
			s.Exit(5)
		}

		io.WriteString(s, oauth2Config.AuthCodeURL(state)+"\n")

		s.Close()

	}

	/**
		SSH HANDLER
	**/
	sshserver.Handle(handleSshSession)
	publicKeyOption := sshserver.PublicKeyAuth(func(ctx sshserver.Context, key sshserver.PublicKey) bool {
		return true // allow all keys, or use ssh.KeysEqual() to compare against known keys
	})

	mux := goji.NewMux()
	mux.HandleFunc(pat.Get("/oauth/v2/callback"), handleOAuth2Callback)

	go http.ListenAndServe(":9999", mux)
	sshserver.ListenAndServe(":2223", nil, publicKeyOption)

	fmt.Println("All goroutines have completed.")

}
