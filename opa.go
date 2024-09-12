package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
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
	input.delegate_fingerprint in input.delegate_fingerprints
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
	module *rego.PreparedEvalQuery
	opa    *sdk.OPA
}

func newOpenPolicyAgentEngine(config []byte, ctx context.Context) (*openPolicyAgentEngine, error) {

	// If not json, we can expect that this is regular config, otherwise load it as an regomodule.
	if !isJson(string(config)) {
		module, err := rego.New(
			rego.Query(`
			x = data.ssh.authz.allow
			vp = data.ssh.authz.validprincipals
			ex = data.ssh.authz.extensions
			co = data.ssh.authz.criticaloptions
			vb = data.ssh.authz.validbefore
			`),
			rego.Module("ssh.authz.rego", string(config)),
		).PrepareForEval(ctx)

		if err != nil {
			return nil, err
		}
		return &openPolicyAgentEngine{
			module: &module,
			opa:    nil,
		}, nil
	}

	// create an instance of the OPA object
	opa, err := sdk.New(ctx, sdk.Options{
		ID:     "ssh.authz.rego",
		Config: bytes.NewReader(config),
	})
	if err != nil {
		return nil, err
	}

	defer opa.Stop(ctx)

	return &openPolicyAgentEngine{
		module: nil,
		opa:    opa,
	}, nil

}

func (engine *openPolicyAgentEngine) Authorize(ctx context.Context, input map[string]interface{}) (*AuthorizationResult, error) {

	if engine.module != nil {
		results, err := engine.module.Eval(ctx, rego.EvalInput(input))

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

	if engine.opa != nil {

		results, err := engine.opa.Decision(ctx, sdk.DecisionOptions{
			Path:  "/ssh/authz",
			Input: input,
		})

		if err != nil {
			return nil, err
		}

		res, ok := results.Result.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("unable to parse result %#v", res)
		}

		if ok := res["allow"].(bool); !ok {
			return nil, fmt.Errorf("evaluation failed, result: %#v", res)
		}

		outValidPrincipals := res["validprincipals"].([]interface{})
		validPrincipals := make([]string, len(outValidPrincipals))
		for idx := range outValidPrincipals {
			validPrincipals[idx] = outValidPrincipals[idx].(string)
		}

		outCriticalOptions := res["criticaloptions"].(map[string]interface{})
		criticalOptions := map[string]string{}
		for k := range outCriticalOptions {
			criticalOptions[k] = outCriticalOptions[k].(string)
		}

		outExtensions := res["extensions"].(map[string]interface{})
		extensions := map[string]string{}
		for k := range outExtensions {
			extensions[k] = outExtensions[k].(string)
		}

		if res["validbefore"] == nil {
			return nil, fmt.Errorf("evaluation failed, result: %#v", results)
		}

		validBefore, _ := res["validbefore"].(json.Number).Int64()

		return &AuthorizationResult{
			ValidPrincipals: validPrincipals,
			CriticalOptions: criticalOptions,
			Extensions:      extensions,
			ValidBefore:     uint64(validBefore),
		}, nil

	}

	return nil, fmt.Errorf("failure during authorize in engine")
}
