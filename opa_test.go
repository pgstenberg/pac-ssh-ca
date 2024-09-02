package main

import (
	"context"
	"fmt"
	"testing"

	sdktest "github.com/open-policy-agent/opa/sdk/test"
)

func TestOpaModuleAuthorizePass(t *testing.T) {

	policyEngine, err := newOpenPolicyAgentEngine([]byte(`
package ssh.authz

import rego.v1

default allow := false

default validprincipals := []
default extensions := {}
default criticaloptions := {}
default validafter := 0
default validbefore := 0

allow if input.foo == "bar"
`), context.Background())

	if err != nil {
		t.Fatal("Unable to load default rego module: ", err)
	}

	input := make(map[string]interface{}, 1)
	input["foo"] = "bar"

	result, err := policyEngine.Authorize(context.Background(), input)

	if err != nil {
		t.Errorf("policy evaluation failed, err: %s, input: %s", err, input)
	}

	t.Logf("result %#v", result)

}

func TestOpaAuthorizePass(t *testing.T) {
	ctx := context.Background()

	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"ssh.authz.rego": `
				package ssh.authz

				import rego.v1

				default allow := false

				default validprincipals := []
				default extensions := {}
				default criticaloptions := {}
				default validafter := 0
				default validbefore := 0

				allow if input.foo == "bar"
			`,
	}))
	if err != nil {
		t.Fatal("unable start mock server: ", err)
	}

	defer server.Stop()

	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		}
	}`, server.URL()))

	t.Logf("server.URL=%s", server.URL())

	policyEngine, err := newOpenPolicyAgentEngine(config, ctx)

	if err != nil {
		t.Fatal("Unable to create policyengine: ", err)
	}

	input := make(map[string]interface{}, 1)
	input["foo"] = "bar"

	result, err := policyEngine.Authorize(context.Background(), input)

	if err != nil {
		t.Errorf("policy evaluation failed, err: %s, input: %s", err, input)
	}

	t.Logf("result %#v", result)

}

func TestOpaModuleAuthorizeFail(t *testing.T) {

	policyEngine, err := newOpenPolicyAgentEngine([]byte(`
package ssh.authz

import rego.v1

default allow := false

default validprincipals := []
default extensions := {}
default criticaloptions := {}
default validafter := 0
default validbefore := 0

allow if input.foo == "bar2"
`), context.Background())

	if err != nil {
		t.Fatal("Unable to load default rego module: ", err)
	}

	input := make(map[string]interface{}, 1)
	input["foo"] = "bar"

	result, err := policyEngine.Authorize(context.Background(), input)

	if err == nil {
		t.Errorf("Expected failure, but got valid result %#v", result)
	}

	t.Logf("Expected error %s", err)

}

func TestOpaAuthorizeFail(t *testing.T) {
	ctx := context.Background()

	// create a mock HTTP bundle server
	server, err := sdktest.NewServer(sdktest.MockBundle("/bundles/bundle.tar.gz", map[string]string{
		"ssh.authz.rego": `
				package ssh.authz

				import rego.v1

				default allow := false

				default validprincipals := []
				default extensions := {}
				default criticaloptions := {}
				default validafter := 0
				default validbefore := 0

				allow if input.foo == "bar2"
			`,
	}))
	if err != nil {
		t.Fatal("unable start mock server: ", err)
	}

	defer server.Stop()

	config := []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundles/bundle.tar.gz"
			}
		}
	}`, server.URL()))

	t.Logf("server.URL=%s", server.URL())

	policyEngine, err := newOpenPolicyAgentEngine(config, ctx)

	if err != nil {
		t.Fatal("Unable to create policyengine: ", err)
	}

	input := make(map[string]interface{}, 1)
	input["foo"] = "bar"

	result, err := policyEngine.Authorize(context.Background(), input)

	if err == nil {
		t.Errorf("Expected failure, but got valid result %#v", result)
	}

	t.Logf("Expected error %s", err)

}
