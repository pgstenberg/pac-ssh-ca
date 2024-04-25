package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

type AuthorizationEngine interface {
	Authorize(context.Context, *AuthorizationInput) (*AuthorizationResult, error)
}

type AuthorizationResult struct {
	ValidPrincipals []string
	CriticalOptions map[string]string
	Extensions      map[string]string
	ValidBefore     uint64
	ValidAfter      uint64
}
type AuthorizationInput struct {
	Principal    string
	ThumbPrint   string
	TicketClaims TicketClaims
}

type OpenPolicyAgentEngine struct {
	query *rego.PreparedEvalQuery
}

func NewOpenPolicyAgentEngine(file string, ctx context.Context) (*OpenPolicyAgentEngine, error) {
	regoModule, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	query, err := rego.New(
		rego.Query(`
		x = data.ssh.authz.allow
		vp = data.ssh.authz.validprincipals
		ex = data.ssh.authz.extensions
		co = data.ssh.authz.criticaloptions
		co = data.ssh.authz.criticaloptions
		vb = data.ssh.authz.validbefore
		va = data.ssh.authz.validafter
		`),
		rego.Module(file, string(regoModule)),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}
	return &OpenPolicyAgentEngine{
		query: &query,
	}, nil
}

func (engine *OpenPolicyAgentEngine) Authorize(ctx context.Context, input *AuthorizationInput) (*AuthorizationResult, error) {
	results, err := engine.query.Eval(ctx, rego.EvalInput(map[string]interface{}{
		"principal":  input.Principal,
		"thumbprint": input.ThumbPrint,
		"state": map[string]interface{}{
			"principal":  input.TicketClaims.StateClaims.Principal,
			"thumbprint": input.TicketClaims.StateClaims.ThumbPrint,
		},
		"ticket": map[string]interface{}{
			"id_token": input.TicketClaims.IdToken,
			"scope":    input.TicketClaims.Scope,
		},
	}))

	if err != nil {
		return nil, err
	} else if len(results) == 0 {
		return nil, errors.New("no result returned from evaluation")
	} else if ok := results[0].Bindings["x"].(bool); !ok {
		return nil, fmt.Errorf("evaluation failed, result: %#v", results)
	}

	outValidPrincipals := results[0].Bindings["vp"].([]interface{})
	validPrincipals := make([]string, len(outValidPrincipals))
	for idx := range outValidPrincipals {
		validPrincipals[idx] = outValidPrincipals[idx].(string)
	}

	outCriticalOptions := results[0].Bindings["co"].(map[string]interface{})
	criticalOptions := map[string]string{}
	for k := range outCriticalOptions {
		criticalOptions[k] = outCriticalOptions[k].(string)
	}

	outExtensions := results[0].Bindings["ex"].(map[string]interface{})
	extensions := map[string]string{}
	for k := range outExtensions {
		extensions[k] = outExtensions[k].(string)
	}

	if results[0].Bindings["va"] == nil || results[0].Bindings["vb"] == nil {
		return nil, fmt.Errorf("evaluation failed, result: %#v", results)
	}

	validAfter, _ := results[0].Bindings["va"].(json.Number).Int64()
	validBefore, _ := results[0].Bindings["vb"].(json.Number).Int64()

	return &AuthorizationResult{
		ValidPrincipals: validPrincipals,
		CriticalOptions: criticalOptions,
		Extensions:      extensions,
		ValidBefore:     uint64(validBefore),
		ValidAfter:      uint64(validAfter),
	}, nil
}
