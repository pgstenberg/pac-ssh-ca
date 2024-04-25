package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type StateClaims struct {
	ThumbPrint string `json:"thumbprint"`
	Principal  string `json:"principal"`
	jwt.RegisteredClaims
}

type TicketClaims struct {
	IdToken string `json:"id_token"`
	Scope   string `json:"scope"`
	jwt.RegisteredClaims
	StateClaims `json:"state"`
}
