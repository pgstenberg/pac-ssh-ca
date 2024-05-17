package main

import (
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestJsonMarshalUnmarshal(t *testing.T) {
	claims := &jwt.MapClaims{}
	value := &hostTicket{
		jwt.RegisteredClaims{
			Subject: "helloworld",
		},
	}
	if err := jsonMarshalUnmarshal[jwt.MapClaims](value, claims); err != nil {
		t.Fatalf("error;%s", err)
	}

	t.Logf("claims=%s", claims)
}
