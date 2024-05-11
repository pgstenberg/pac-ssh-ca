package main

import (
	jwt "github.com/golang-jwt/jwt/v5"
)

type UserTicket struct {
	IdToken string `json:"id_token"`
	Scope   string `json:"scope"`
	jwt.RegisteredClaims
	State `json:"state"`
}

type HostTicket struct {
	jwt.RegisteredClaims
}

func JwtMapClaims(value any) (*jwt.MapClaims, error) {
	claims := jwt.MapClaims{}
	if err := marshalUnmarshal(&claims, value); err != nil {
		return nil, err
	}

	return &claims, nil
}
