package main

import (
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

type certificateAuthority struct {
	signer     *ssh.Signer
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	delegates []*ssh.PublicKey
}

func loadDelegates(delegates [][]byte) ([]*ssh.PublicKey, error) {
	list := []*ssh.PublicKey{}
	for _, issuerData := range delegates {
		if len(issuerData) == 0 {
			continue
		}
		k, _, _, _, err := ssh.ParseAuthorizedKey(issuerData)
		if err != nil {
			return nil, err
		}
		list = append(list, &k)
	}

	return list, nil
}

func newCertificateAuthority(privatekey []byte, delegates [][]byte) (*certificateAuthority, error) {
	pk, err := ssh.ParseRawPrivateKey(privatekey)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(pk)
	if err != nil {
		return nil, err
	}

	ca := &certificateAuthority{
		signer:     &signer,
		publicKey:  &(pk.(*rsa.PrivateKey)).PublicKey,
		privateKey: pk.(*rsa.PrivateKey),
	}

	ca.delegates = []*ssh.PublicKey{}

	if len(delegates) > 0 {
		ca.delegates, err = loadDelegates(delegates)
		if err != nil {
			return nil, fmt.Errorf("unable to load delegates, err: %s", err)
		}
	}

	return ca, nil
}
