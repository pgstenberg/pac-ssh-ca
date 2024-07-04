package main

import (
	"fmt"
	"log"
	"math/rand"
	"testing"
)

func randomPort() int {
	p := rand.Intn(65535)
	if p != 22 {
		return p
	}
	return randomPort()
}

func TestAddrToPort(t *testing.T) {

	p0 := randomPort()

	p, err := addrToPort(fmt.Sprintf("127.0.0.1:%d", p0))

	if err != nil {
		t.Fatalf("error: %s", err)
	}

	if p != p0 {
		t.Fatalf("port %d, did not match expected port %d", p, p0)
	}
}

func TestGenerateDefaultSshCommand(t *testing.T) {
	cmd := generateSshCommand("user", "host", 22, "foobar", "~/.ssh/id_rsa")
	t.Logf("cmd=%s", cmd)
}
func TestGenerateSshCommandNonePort22NoneRSAIdentityFile(t *testing.T) {

	p := randomPort()
	identityFilePath := "~/.ssh/id_ed25519"

	expectedCmd := fmt.Sprintf("ssh -i %s -p %d user@host 'foobar'", identityFilePath, p)
	cmd := generateSshCommand("user", "host", p, "foobar", identityFilePath)

	log.Printf("expectedCmd=%s", expectedCmd)
	log.Printf("cmd=%s", cmd)

	if expectedCmd != cmd {
		log.Fatalf("[%s] did not match [%s]", cmd, expectedCmd)
	}

}

func TestJsonMarshalUnmarshal(t *testing.T) {

	type testStruct struct {
		Foo string `json:"foo"`
		Bar string `json:"bar"`
	}

	var target map[string]interface{}
	if err := jsonMarshalUnmarshal[map[string]interface{}](testStruct{
		Foo: "foo",
		Bar: "bar",
	}, &target); err != nil {
		t.Fatalf("error: %s", err)
	}

	if target["foo"].(string) != "foo" {
		t.Fatalf("target=%s, did not match %s", target["foo"].(string), "foo")
	}
	if target["bar"].(string) != "bar" {
		t.Fatalf("target=%s, did not match %s", target["bar"].(string), "bar")
	}
}

func TestStringSliceToBytes(t *testing.T) {

	bytes := stringSliceToBytes([]string{
		"foo",
		"bar",
	})

	if string(bytes[0]) != "foo" {
		t.Fatalf("bytes=%s, did not match %s", string(bytes[0]), "foo")
	}
	if string(bytes[1]) != "bar" {
		t.Fatalf("bytes=%s, did not match %s", string(bytes[1]), "bar")
	}
}
