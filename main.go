package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	ssh "github.com/gliderlabs/ssh"
	jwt "github.com/golang-jwt/jwt/v5"
	"goji.io"
	"goji.io/pat"
	cryptossh "golang.org/x/crypto/ssh"
)

func main() {

	const (
		AUD_HOST  = "host"
		AUD_USER  = "user"
		AUD_STATE = "state"
	)

	issuer, err := os.Hostname()
	if err != nil {
		log.Fatal("Unable to determine issuer based on hostname: ", err)
	}

	var configFile string
	var authzmoduleFile string
	var privatekeyFile string
	flag.StringVar(&configFile, "config", "./config.yaml", "path to config file")
	flag.StringVar(&authzmoduleFile, "authzmodule", "./default.rego", "path to opa rego module file")
	flag.StringVar(&privatekeyFile, "privatekey", "./ca", "path ca private key")

	// Actually parse the flags
	flag.Parse()

	config, err := newConfig(configFile)
	if err != nil {
		log.Fatal("Unable to load configuration: ", configFile)
	}

	policyEngine, err := newOpenPolicyAgentEngine(authzmoduleFile, context.Background())
	if err != nil {
		log.Fatal("Unable to load policy engine: ", err)
	}

	privateBytes, err := os.ReadFile(privatekeyFile)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	ca, err := newCertificateAuthority(privateBytes, stringSliceToBytes(config.Delegation.Delegates))
	if err != nil {
		log.Fatal("Failed to load user certificate authority: ", err)
	}

	k, err := cryptossh.NewPublicKey(ca.publicKey)
	if err != nil {
		log.Fatal("Failed to create public key: ", err)
	}
	presentedPublicKey := string(cryptossh.MarshalAuthorizedKey(k))

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: config.HttpTransport.InsecureSkipVerify}

	/**
		SSH SERVER
	**/
	sshserver := &ssh.Server{
		Addr: config.SshServer.Addr,
		Handler: func(s ssh.Session) {

			// If emtpy command, try issue new tickets (JWTs)
			if s.RawCommand() == "" {

				// if public key match any delegates we can expect this to be a host signing request
				for _, delegate := range ca.delegates {
					if cryptossh.FingerprintSHA256(*delegate) == cryptossh.FingerprintSHA256(s.PublicKey()) {
						claims := &jwt.MapClaims{}
						t0 := time.Now()

						td, err := time.ParseDuration(config.Delegation.TicketTimeToLive)
						if err != nil {
							log.Printf("failed to parse ticket duration; err=%s", err)
							s.Exit(5)
							return
						}

						if err := jsonMarshalUnmarshal[jwt.MapClaims](&HostTicket{
							jwt.RegisteredClaims{
								Subject:   s.User(),
								Audience:  jwt.ClaimStrings{AUD_HOST},
								NotBefore: jwt.NewNumericDate(t0),
								IssuedAt:  jwt.NewNumericDate(t0),
								ExpiresAt: jwt.NewNumericDate(time.Now().Add(td)),
								Issuer:    issuer,
							},
						}, claims); err != nil {
							log.Printf("failed during host ticket creation; err=%s", err)
							s.Exit(5)
							return
						}

						t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
						st, err := t.SignedString(ca.privateKey)
						if err != nil {
							log.Printf("Unable to sign jwt; err=%s", err)
							s.Exit(5)
							return
						}

						io.WriteString(s, st+"\n")
						s.Close()
						return
					}
				}

				// Otherwise we create a new authorization request for openid-connect federated login for users
				federation, err := getFederationInstance(s.Context(), config)
				if err != nil {
					log.Printf("failed during getFederationInstance; %s", err)
					s.Exit(5)
					return
				}

				claims := &jwt.MapClaims{}
				t0 := time.Now()
				td, err := time.ParseDuration(config.Delegation.TicketTimeToLive)
				if err != nil {
					log.Printf("failed to parse ticket duration; err=%s", err)
					s.Exit(5)
					return
				}

				if err := jsonMarshalUnmarshal[jwt.MapClaims](state{
					Fingerprint: cryptossh.FingerprintSHA256(s.PublicKey()),
					RegisteredClaims: jwt.RegisteredClaims{
						Subject:   s.User(),
						NotBefore: jwt.NewNumericDate(t0),
						IssuedAt:  jwt.NewNumericDate(t0),
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(td)),
						Audience:  jwt.ClaimStrings{AUD_STATE},
						Issuer:    issuer,
					},
				}, claims); err != nil {
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

				return
			}

			// If an input was given we can espect this to be a signed ticket (JWT)
			jwtParser := jwt.NewParser(
				jwt.WithIssuedAt(),
				jwt.WithExpirationRequired(),
				jwt.WithIssuer(issuer),
			)

			st, err := jwtParser.ParseWithClaims(s.RawCommand(), &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
				return ca.publicKey, nil
			})
			if err != nil {
				log.Printf("jwt verify failed, err: %s", err)
				s.Exit(5)
				return
			}

			// Create input for policy evaluation
			var input map[string]interface{}
			err = jsonMarshalUnmarshal[map[string]interface{}](st.Claims, &input)
			if err != nil {
				log.Printf("unable to create authorization input: %s", err)
				s.Exit(5)
				return
			}

			input["username"] = s.User()
			input["fingerprint"] = cryptossh.FingerprintSHA256(s.PublicKey())
			addrport, err := netip.ParseAddrPort(s.RemoteAddr().String())
			if err != nil {
				log.Printf("unable to determine required remoteaddr: %s", err)
				s.Exit(5)
				return
			}
			input["addr"] = addrport.Addr().String()

			// Try to reverse-lookup remote addr
			if addr, err := net.LookupAddr(input["addr"].(string)); err == nil {
				input["addr"] = addr[0]
			}

			// Policy Evalution
			result, err := policyEngine.Authorize(s.Context(), input)
			if err != nil {
				log.Printf("policy evaluation failed, err: %s, input: %s", err, input)
				s.Exit(5)
				return
			}

			permissions := cryptossh.Permissions{
				CriticalOptions: result.CriticalOptions,
				Extensions:      result.Extensions,
			}

			cert := &cryptossh.Certificate{
				CertType:        cryptossh.UserCert,
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

			io.WriteString(s, string(cryptossh.MarshalAuthorizedKey(cert)))
			s.Close()

		},
	}
	sshserver.SetOption(ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		return true // allow all keys, or use ssh.KeysEqual() to compare against known keys
	}))

	/**
		HTTP SERVER
	**/
	muxHttpService := goji.NewMux()
	muxHttpService.HandleFunc(pat.Get("/oauth/v2/callback"), func(w http.ResponseWriter, r *http.Request) {

		federation, err := getFederationInstance(r.Context(), config)
		if err != nil {
			log.Printf("unable to get federation instance: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		stateValue := r.URL.Query().Get("state")

		jwtParser := jwt.NewParser(
			jwt.WithIssuedAt(),
			jwt.WithExpirationRequired(),
			jwt.WithAudience("state"),
			jwt.WithIssuer(issuer),
		)

		st, err := jwtParser.ParseWithClaims(stateValue, &state{}, func(token *jwt.Token) (interface{}, error) {
			return ca.publicKey, nil
		})
		if err != nil {
			log.Printf("state jwt validation failed: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		state, ok := st.Claims.(*state)
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

		parsedIdToken, err := federation.oidcIDTokenVerifier.Verify(r.Context(), idToken)
		if err != nil {
			log.Printf("id_token verification failed.")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		claims := &jwt.MapClaims{}
		t0 := time.Now()
		err = jsonMarshalUnmarshal[jwt.MapClaims](UserTicket{
			Scope: scope,
			state: *state,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   parsedIdToken.Subject,
				Audience:  jwt.ClaimStrings{AUD_USER},
				NotBefore: jwt.NewNumericDate(t0),
				IssuedAt:  jwt.NewNumericDate(t0),
				ExpiresAt: jwt.NewNumericDate(parsedIdToken.Expiry),
				Issuer:    issuer,
			},
		}, claims)
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
	})
	muxHttpService.HandleFunc(pat.Get("/crypto/public"), func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, presentedPublicKey)
	})
	httpserver := &http.Server{
		Handler: muxHttpService,
		Addr:    config.HttpServer.Addr,
	}

	go sshserver.ListenAndServe()
	go httpserver.ListenAndServe()

	log.Printf("Servers started.")

	// create a channel to subscribe ctrl+c/SIGINT event
	sigInterruptChannel := make(chan os.Signal, 1)
	signal.Notify(sigInterruptChannel, os.Interrupt)
	// block execution from continuing further until SIGINT comes
	<-sigInterruptChannel

	// create a context which will expire after 4 seconds of grace period
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*4)
	defer cancel()

	log.Printf("Gracefully closing down servers...")

	go httpserver.Shutdown(ctx)
	go sshserver.Shutdown(ctx)

	// wait until ctx ends (which will happen after 4 seconds)
	<-ctx.Done()

	log.Printf("Successfully shutdown.")

}
