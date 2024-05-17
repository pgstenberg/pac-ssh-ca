package main

import (
	"testing"
)

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
