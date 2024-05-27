package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetFederationInstance(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		const response string = `
{
	"supported_response_types": ["code", "code id_token", "token id_token"],
	"supported_scopes": ["openid", "profile", "email"],
	"algoritms": ["HS256"],
	"endpoints": {
		"authorization": "http://p.example.org/oic",
		"token": "http://p.example.org/oic",
		"registration": "http://p.example.org/oic",
		"userinfo": "http://p.example.org/oic",
		"check_id": "http://p.example.org/oic"
	},
	"issuer": "urn:foo:bar"
}
		`
		io.WriteString(w, response)
	}))

	defer server.Close()

	config := &Config{}
	config.Federation.OpenIdConnect.Issuer = server.URL

	ctx := context.Background()

	fed01, err := getFederationInstance(ctx, config)
	if err != nil {
		t.Fatalf("unexpected error; %s", err)
	}
	fed02, err := getFederationInstance(ctx, config)
	if err != nil {
		t.Fatalf("unexpected error; %s", err)
	}

	if fed01 != fed02 {
		t.Fatalf("fed01 (%#v) and fed02 (%#v) is not the same instances.", fed01, fed02)
	}

}
