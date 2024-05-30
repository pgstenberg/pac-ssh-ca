package main

import (
	"context"
)

type AuthorizationResult struct {
	ValidPrincipals []string
	CriticalOptions map[string]string
	Extensions      map[string]string
	ValidBefore     uint64
}

type AuthorizationInput map[string]interface{}

type AuthorizationEngine interface {
	Authorize(context.Context, AuthorizationInput) (*AuthorizationResult, error)
}
