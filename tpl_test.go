package main

import (
	"bytes"
	"testing"
)

func TestGeneratePage(t *testing.T) {

	var b bytes.Buffer

	if err := generatePage(&b, "hello world"); err != nil {
		t.Fatalf("error=%s", err)
	}

	t.Log(b.String())
}
