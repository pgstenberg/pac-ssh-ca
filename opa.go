package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/rego"
)

type openPolicyAgentEngine struct {
	query *rego.PreparedEvalQuery
}

func newOpenPolicyAgentEngine(file string, ctx context.Context) (*openPolicyAgentEngine, error) {
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
	return &openPolicyAgentEngine{
		query: &query,
	}, nil
}

func (engine *openPolicyAgentEngine) Authorize(ctx context.Context, input map[string]interface{}) (*AuthorizationResult, error) {

	results, err := engine.query.Eval(ctx, rego.EvalInput(input))

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
