package main

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v2"
)

// Config struct for webapp config
type Config struct {
	Federation struct {
		OpenIdConnect struct {
			StateTimeToLive string   `yaml:"state_ttl,omitempty"`
			Issuer          string   `yaml:"issuer" validate:"required"`
			TokenEndpoint   string   `yaml:"token_endpoint,omitempty"`
			PrincipalClaim  string   `yaml:"principal_claim,omitempty"`
			ClientId        string   `yaml:"client_id"`
			ClientSecret    string   `yaml:"client_secret"`
			RedirectUri     string   `yaml:"redirect_uri"`
			Scopes          []string `yaml:"scopes,omitempty"`
			ValidateIssuer  bool     `yaml:"validate_issuer,omitempty"`
		} `yaml:"openid_connect,omitempty"`
	} `yaml:"federation,omitempty"`
	Delegation struct {
		TicketTimeToLive string   `yaml:"ticket_ttl"`
		Delegates        []string `yaml:"delegates,omitempty"`
	} `yaml:"delegation,omitempty"`
	HttpTransport struct {
		InsecureSkipVerify bool `yaml:"insecure_skip_verify,omitempty"`
	} `yaml:"http_transport,omitempty"`
	HttpServer struct {
		Addr string `yaml:"addr,omitempty"`
	} `yaml:"http_server,omitempty"`
	SshServer struct {
		Addr string `yaml:"addr,omitempty"`
	} `yaml:"ssh_server,omitempty"`
}

func newConfig(configData []byte) (*Config, error) {

	config := &Config{}

	if len(configData) == 0 {
		return nil, fmt.Errorf("no configuration data was provided")
	}

	d := yaml.NewDecoder(bytes.NewReader(configData))
	d.SetStrict(true)

	if err := d.Decode(&config); err != nil {
		return nil, err
	}

	// Check if config is sufficient
	if len(config.Delegation.Delegates) == 0 &&
		// Check Required Fields for OIDC Federation
		(config.Federation.OpenIdConnect.Issuer == "" ||
			config.Federation.OpenIdConnect.ClientId == "" ||
			config.Federation.OpenIdConnect.ClientSecret == "" ||
			config.Federation.OpenIdConnect.RedirectUri == "") {
		return nil, fmt.Errorf("either one delegate or proper federation need to be provided")
	}

	return config, nil
}
