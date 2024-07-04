package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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

	var privatekeyFile string
	var configFile string
	var authzmoduleFile string
	flag.StringVar(&privatekeyFile, "privatekey", "./ca", "path ca private key")
	flag.StringVar(&configFile, "config", "", "path to config file")
	flag.StringVar(&authzmoduleFile, "authzmodule", "", "path to opa rego module file")

	// Actually parse the flags
	flag.Parse()

	config := &Config{}
	if configFile != "" {
		configData, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Unable to load config-file: %s", err)
		}

		config, err = newConfig(configData)
		if err != nil {
			log.Fatalf("Unable to create configuration: %s, err: %s", configFile, err)
		}
	}

	issuer, err := os.Hostname()
	if err != nil {
		log.Fatal("Unable to determine issuer based on hostname: ", err)
	}
	if config.Issuer != "" {
		issuer = config.Issuer
	}

	log.Printf("Successfully setup token issuer: %s", issuer)

	var resolver *resolver = newResolver(config.ReverseLookupDns)

	policyEngine, err := newOpenPolicyAgentEngine([]byte(DEFAULT_OPA_REGO), context.Background())
	if err != nil {
		log.Fatal("Unable to load default rego module: ", err)
	}
	if authzmoduleFile != "" {
		regoModule, err := os.ReadFile(authzmoduleFile)
		if err != nil {
			log.Fatal("Unable to load regomodule: ", authzmoduleFile)
		}
		policyEngine, err = newOpenPolicyAgentEngine(regoModule, context.Background())
		if err != nil {
			log.Fatal("Unable to load policy engine: ", err)
		}
	}

	if _, err := os.Stat(privatekeyFile); errors.Is(err, os.ErrNotExist) {
		log.Printf("File %s do not exists, generating new privatekey...", privatekeyFile)

		privateKey, err := generatePrivateKey(2048)
		if err != nil {
			log.Fatal("Failed to generate new private key: ", err)
		}

		if err := os.WriteFile(privatekeyFile, privateKey, 0600); err != nil {
			log.Fatal("Failed to write new private key: ", err)
		}

		log.Printf("Successfully generated and store new private key: %s", privatekeyFile)
	}

	privateBytes, err := os.ReadFile(privatekeyFile)
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	delegates := [][]byte{{}}
	if config.Delegation.Delegates != nil {
		delegates = stringSliceToBytes(config.Delegation.Delegates)
	}
	ca, err := newCertificateAuthority(privateBytes, delegates)
	if err != nil {
		log.Fatal("Failed to load user certificate authority: ", err)
	}

	for _, d := range ca.delegates {
		log.Printf("Successfully loaded delegate: %s", string(cryptossh.MarshalAuthorizedKey(*d)))
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
		Addr:        config.SshServer.Addr,
		HostSigners: []ssh.Signer{*ca.signer},
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
							DelegateFingerprint: cryptossh.FingerprintSHA256(*delegate),
							RegisteredClaims: jwt.RegisteredClaims{
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
						s.Exit(0)
						return
					}
				}

				fmt.Println("TYPE:")
				fmt.Println(s.PublicKey().Type())

				// Otherwise we create a new authorization request for openid-connect federated login for users
				federation, err := getFederationInstance(s.Context(), config)
				if err != nil {
					log.Printf("failed during getFederationInstance; %s", err)
					s.Exit(5)
					return
				}

				claims := &jwt.MapClaims{}
				t0 := time.Now()
				td, err := time.ParseDuration(config.Federation.OpenIdConnect.StateTimeToLive)
				if err != nil {
					log.Printf("failed to parse ticket duration; err=%s", err)
					s.Exit(5)
					return
				}

				if err := jsonMarshalUnmarshal[jwt.MapClaims](state{
					Fingerprint: cryptossh.FingerprintSHA256(s.PublicKey()),
					KeyFormat:   s.PublicKey().Type(),
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

			st, err := jwtParser.ParseWithClaims(s.RawCommand(), &jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
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
			input["delegate_fingerprints"] = ca.delegateFingerprints()
			input["fingerprint"] = cryptossh.FingerprintSHA256(s.PublicKey())
			input["addr"], err = resolver.reverseLookup(s.Context(), s.RemoteAddr().String())
			if err != nil {
				log.Printf("failure occured during reverselookup: %s", err)
				s.Exit(5)
				return
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

			var certType uint32
			aud, err := st.Claims.GetAudience()
			if err != nil {
				log.Printf("Unable to determine aud, err:%s", err)
				s.Exit(5)
				return
			}
			switch aud[0] {
			case AUD_HOST:
				certType = cryptossh.HostCert
			case AUD_USER:
				certType = cryptossh.UserCert
			}

			cert := &cryptossh.Certificate{
				CertType:        certType,
				Key:             s.PublicKey(),
				ValidPrincipals: result.ValidPrincipals,
				Permissions:     permissions,
				ValidAfter:      uint64(time.Now().Unix()),
				ValidBefore:     result.ValidBefore,
			}

			if err := cert.SignCert(rand.Reader, *ca.signer); err != nil {
				log.Printf("failed to sign certificate; %s", err)
				s.Exit(4)
				return
			}

			log.Printf("new certificate issued; principal=%s, fingerprint=%s, expires=%s",
				result.ValidPrincipals,
				cryptossh.FingerprintSHA256(cert.Key),
				time.Unix(int64(result.ValidBefore), 0),
			)

			io.WriteString(s, string(cryptossh.MarshalAuthorizedKey(cert)))
			s.Exit(0)

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
			log.Printf("state jwt validation failed, jwt=%s, err=%s", stateValue, err)
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

		log.Printf("Verifying id_token=%s", idToken)

		parsedIdToken, err := federation.oidcIDTokenVerifier.Verify(r.Context(), idToken)
		if err != nil {
			log.Printf("id_token verification failed, err=%s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		principalClaim := parsedIdToken.Subject

		if config.Federation.OpenIdConnect.PrincipalClaim != "" {
			var claims jwt.MapClaims
			if err := parsedIdToken.Claims(&claims); err != nil {
				log.Printf("unable to parse id_token, err=%s", err)
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			principalClaim = claims[config.Federation.OpenIdConnect.PrincipalClaim].(string)
		}

		claims := &jwt.MapClaims{}
		t0 := time.Now()
		err = jsonMarshalUnmarshal[jwt.MapClaims](UserTicket{
			Scope: scope,
			state: *state,
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   principalClaim,
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

		// Generate ssh command for the user
		cmd := generateSshCommand(principalClaim, issuer, 22, s, expectedIdentityFilePath(state.KeyFormat))
		if config.SshServer.Addr != "" {
			if p, err := addrToPort(config.SshServer.Addr); err == nil {
				cmd = generateSshCommand(principalClaim, issuer, p, s, expectedIdentityFilePath(state.KeyFormat))
			}
		}

		if err := generatePage(w, cmd, expectedIdentityFilePath(state.KeyFormat)); err != nil {
			log.Printf("unable to generate template, err: %s", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
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
