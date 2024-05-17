package main

import (
	"os"

	"gopkg.in/yaml.v2"
)

// Config struct for webapp config
type Config struct {
	Federation struct {
		OpenIdConnect struct {
			StateTimeToLive string   `yaml:"state_ttl"`
			Issuer          string   `yaml:"issuer"`
			ClientId        string   `yaml:"client_id"`
			ClientSecret    string   `yaml:"client_secret"`
			RedirectUri     string   `yaml:"redirect_uri"`
			Scopes          []string `yaml:"scopes"`
		} `yaml:"openid_connect"`
	} `yaml:"federation"`
	Delegation struct {
		TicketTimeToLive string   `yaml:"ticket_ttl"`
		Delegates        []string `yaml:"delegates"`
	} `yaml:"delegation"`
	HttpTransport struct {
		InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
	} `yaml:"http_transport"`
	HttpServer struct {
		Addr string `yaml:"addr"`
	} `yaml:"http_server"`
	SshServer struct {
		Addr string `yaml:"addr"`
	} `yaml:"ssh_server"`
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
