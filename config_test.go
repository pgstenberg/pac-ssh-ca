package main

import (
	"strings"
	"testing"
)

func TestEmptyConfig(t *testing.T) {
	const emptyConfig string = ""
	config, err := newConfig([]byte(emptyConfig))
	if err == nil {
		t.Fatalf("expected error with empty config, config=%#v", config)
	}
	t.Logf("Expected error received; %s", err)
}

func TestInsuffientConfig(t *testing.T) {
	const emptyConfig string = `
federation:
    openid_connect:
        client_id: test
        client_secret: secret
	`
	config, err := newConfig([]byte(strings.TrimSpace(emptyConfig)))
	if err == nil {
		t.Fatalf("expected error with empty config, config=%#v", config)
	}
	t.Logf("Expected error received; %s", err)

}
