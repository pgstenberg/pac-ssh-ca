package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	sshserver "github.com/gliderlabs/ssh"
	jwt "github.com/golang-jwt/jwt/v5"
	"goji.io"
	"goji.io/pat"
	"golang.org/x/crypto/ssh"
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

	policyEngine, err := NewOpenPolicyAgentEngine(authzmoduleFile, context.Background())
	if err != nil {
		log.Fatal("Unable to load policy engine: ", err)
	}

	privateBytes, err := os.ReadFile(privatekeyFile)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	ca, err := NewCertificateAuthority(privateBytes, nil)
	if err != nil {
		log.Fatal("Failed to load user certificate authority: ", err)
	}

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	handleOAuth2Callback := func(w http.ResponseWriter, r *http.Request) {

		federation, err := getFederationInstance(r.Context(), config)
		if err != nil {
			log.Printf("unable to get federation instance: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		stateValue := r.URL.Query().Get("state")

		st, err := jwt.ParseWithClaims(stateValue, &State{}, func(token *jwt.Token) (interface{}, error) {
			return ca.publicKey, nil
		})
		if err != nil {
			log.Printf("state jwt validation failed: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		state, ok := st.Claims.(*State)
		if !ok {
			log.Printf("unable to typecast stateclaims")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		oauth2Token, err := federation.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
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

		scope := strings.Join(federation.oauth2Config.Scopes, " ")
		if oauth2Token.Extra("scope") != nil {
			scope = oauth2Token.Extra("scope").(string)
		}

		if _, err := federation.oidcIDTokenVerifier.Verify(r.Context(), idToken); err != nil {
			log.Printf("id_token verification failed.")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		claims, err := JwtMapClaims(UserTicket{
			IdToken: idToken,
			Scope:   scope,
			State:   *state,
		})
		if err != nil {
			log.Printf("unable to sign jwt: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		s, err := t.SignedString(ca.privateKey)
		if err != nil {
			log.Printf("unable to sign jwt: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		io.WriteString(w, s)
	}

	handleSshSession := func(s sshserver.Session) {

		cmd := s.RawCommand()

		if cmd != "" {

			/**
				PARSE JWT
			**/
			st, err := jwt.ParseWithClaims(cmd, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
				return ca.publicKey, nil
			})
			if err != nil {
				log.Printf("jwt verify failed, err: %s", err)
				s.Exit(5)
				return
			}

			input, err := AnyToMap(st.Claims)
			if err != nil {
				log.Printf("unable to create authorization input: %s", err)
				s.Exit(5)
				return
			}

			/**
				POLICTY EVALUATION
			**/

			result, err := policyEngine.Authorize(s.Context(), input)
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

			if err := cert.SignCert(rand.Reader, *ca.signer); err != nil {
				log.Printf("failed to sign certificate; %s", err)
				s.Exit(4)
				return
			}

			io.WriteString(s, string(ssh.MarshalAuthorizedKey(cert)))
			s.Close()
		}

		/**
			NEW AUTHORIZATION REQUEST
		**/

		federation, err := getFederationInstance(s.Context(), config)
		if err != nil {
			log.Printf("failed during getFederationInstance; %s", err)
			s.Exit(5)
			return
		}

		claims, err := JwtMapClaims(State{
			Principal:  s.User(),
			Thumbprint: ssh.FingerprintSHA256(s.PublicKey()),
		})
		if err != nil {
			log.Printf("failed during claims marshaling; %s", err)
			s.Exit(5)
			return
		}

		t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		state, err := t.SignedString(ca.privateKey)
		if err != nil {
			log.Printf("failed during jwt signing; %s", err)
			s.Exit(5)
			return
		}

		io.WriteString(s, federation.oauth2Config.AuthCodeURL(state)+"\n")

		s.Close()

	}

	/**
		SSH HANDLER
	**/
	sshserver.Handle(handleSshSession)
	publicKeyOption := sshserver.PublicKeyAuth(func(ctx sshserver.Context, key sshserver.PublicKey) bool {
		return true // allow all keys, or use ssh.KeysEqual() to compare against known keys
	})

	muxHttpService := goji.NewMux()
	muxHttpService.HandleFunc(pat.Get("/oauth/v2/callback"), handleOAuth2Callback)
	muxHttpService.HandleFunc(pat.Get("/crypto/public"), func(w http.ResponseWriter, r *http.Request) {

		k, err := ssh.NewPublicKey(ca.publicKey)

		if err != nil {
			log.Printf("unable to create ssh public key: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		io.WriteString(w, string(k.Marshal()))
	})
	httpserver := &http.Server{
		Handler: muxHttpService,
		Addr:    ":9999",
	}

	go sshserver.ListenAndServe(":2223", nil, publicKeyOption)
	go httpserver.ListenAndServe()

	// create a channel to subscribe ctrl+c/SIGINT event
	sigInterruptChannel := make(chan os.Signal, 1)
	signal.Notify(sigInterruptChannel, os.Interrupt)
	// block execution from continuing further until SIGINT comes
	<-sigInterruptChannel

	// create a context which will expire after 4 seconds of grace period
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()

	go httpserver.Shutdown(ctx)

	// wait until ctx ends (which will happen after 4 seconds)
	<-ctx.Done()

}
