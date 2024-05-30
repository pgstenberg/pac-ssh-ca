package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

const DEFAULT_OPA_REGO = `
package ssh.authz

import rego.v1

default allow := false

default validprincipals := []
default extensions := {}
default criticaloptions := {}
default validafter := 0
default validbefore := 0

allow if {
    "user" in input.aud
    input.sub == input.state.sub
    input.sub == input.username
    input.fingerprint == input.state.fingerprint
}
allow if {
    "host" in input.aud
    trim_suffix(input.sub, ".") == trim_suffix(input.addr, ".")
    input.sub == input.username
}

validprincipals = [
	input.sub
] if allow

validbefore = input.exp if {
    allow
    "user" in input.aud
}
validbefore = floor(((time.now_ns() + time.parse_duration_ns("15m")) / 1000000000)) if {
    allow
    "host" in input.aud
}

extensions = {
	"permit-X11-forwarding":   "",
	"permit-agent-forwarding": "",
	"permit-port-forwarding":  "",
	"permit-pty":              "",
	"permit-user-rc":          "",
} if {
    allow
    "user" in input.aud
}
`

type openPolicyAgentEngine struct {
	query *rego.PreparedEvalQuery
}

func newOpenPolicyAgentEngine(regoModule []byte, ctx context.Context) (*openPolicyAgentEngine, error) {

	query, err := rego.New(
		rego.Query(`
		x = data.ssh.authz.allow
		vp = data.ssh.authz.validprincipals
		ex = data.ssh.authz.extensions
		co = data.ssh.authz.criticaloptions
		co = data.ssh.authz.criticaloptions
		vb = data.ssh.authz.validbefore
		`),
		rego.Module("ssh.authz.rego", string(regoModule)),
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

	if results[0].Bindings["vb"] == nil {
		return nil, fmt.Errorf("evaluation failed, result: %#v", results)
	}

	validBefore, _ := results[0].Bindings["vb"].(json.Number).Int64()

	return &AuthorizationResult{
		ValidPrincipals: validPrincipals,
		CriticalOptions: criticalOptions,
		Extensions:      extensions,
		ValidBefore:     uint64(validBefore),
	}, nil
}
