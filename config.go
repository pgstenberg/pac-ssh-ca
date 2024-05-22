package main

import (
	"os"

	"gopkg.in/yaml.v2"
)

// Config struct for webapp config
type Config struct {
	Federation struct {
		OpenIdConnect struct {
			StateTimeToLive string   `yaml:"state_ttl,omitempty"`
			Issuer          string   `yaml:"issuer"`
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

func newConfig(configFile string) (*Config, error) {

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
