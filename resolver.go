package main

import (
	"context"
	"net"
	"net/netip"
	"time"
)

type resolver struct {
	netResolver *net.Resolver
}

func newResolver(dns string) *resolver {
	if dns != "" {
		return &resolver{
			netResolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout: time.Millisecond * time.Duration(10000),
					}
					return d.DialContext(ctx, network, "dns:53")
				},
			},
		}
	}

	return &resolver{
		netResolver: net.DefaultResolver,
	}
}

func (resolver *resolver) reverseLookup(ctx context.Context, ip string) (string, error) {
	addrport, err := netip.ParseAddrPort(ip)
	if err != nil {
		return "", err
	}

	addr := addrport.Addr().String()
	if result, err := resolver.netResolver.LookupAddr(ctx, addr); err == nil {
		if len(result) == 1 {
			addr = result[0]
		}
	}

	return addr, nil
}
