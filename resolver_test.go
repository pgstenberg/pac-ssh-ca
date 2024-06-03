package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestReverseLookup(t *testing.T) {
	resolver := newResolver("")
	ctx := context.Background()

	const domain = "google.se"

	ips, _ := net.LookupIP(domain)

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			t.Logf("%s resolved to %s", domain, ip)

			reverseLookupDomain, err := resolver.reverseLookup(ctx, fmt.Sprintf("%s:443", ip))
			if err != nil {
				t.Fatalf("error occured during reverselookup; %s", err)
			}
			if strings.TrimSuffix(domain, ".") != strings.TrimSuffix(reverseLookupDomain, ".") {
				t.Fatalf("reverselookup %s did not match domain %s", reverseLookupDomain, domain)
			}
			t.Logf("Reverse-lookup %s to %s", ip, reverseLookupDomain)
		}
	}
}
