package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type UserTicket struct {
	Scope string `json:"scope"`
	jwt.RegisteredClaims
	state `json:"state"`
}

type HostTicket struct {
	DelegateFingerprint string `json:"delegate_fingerprint"`
	jwt.RegisteredClaims
}
