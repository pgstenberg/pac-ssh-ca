package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type userTicket struct {
	IdToken string `json:"id_token"`
	Scope   string `json:"scope"`
	jwt.RegisteredClaims
	state `json:"state"`
}

type hostTicket struct {
	jwt.RegisteredClaims
}
