package main

import (
	"crypto/rsa"
	"fmt"

	cryptossh "golang.org/x/crypto/ssh"
)

type certificateAuthority struct {
	signer     *cryptossh.Signer
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	delegates []*cryptossh.PublicKey
}

func loadDelegates(delegates [][]byte) ([]*cryptossh.PublicKey, error) {
	list := []*cryptossh.PublicKey{}
	for _, issuerData := range delegates {
		if len(issuerData) == 0 {
			continue
		}
		k, _, _, _, err := cryptossh.ParseAuthorizedKey(issuerData)
		if err != nil {
			return nil, err
		}
		list = append(list, &k)
	}

	return list, nil
}

func (ca *certificateAuthority) delegateFingerprints() []string {
	delegateFingerprints := []string{}
	for _, delegate := range ca.delegates {
		delegateFingerprints = append(delegateFingerprints, cryptossh.FingerprintSHA256(*delegate))
	}
	return delegateFingerprints
}

func newCertificateAuthority(privatekey []byte, delegates [][]byte) (*certificateAuthority, error) {
	pk, err := cryptossh.ParseRawPrivateKey(privatekey)
	if err != nil {
		return nil, err
	}

	signer, err := cryptossh.NewSignerFromKey(pk)
	if err != nil {
		return nil, err
	}

	ca := &certificateAuthority{
		signer:     &signer,
		publicKey:  &(pk.(*rsa.PrivateKey)).PublicKey,
		privateKey: pk.(*rsa.PrivateKey),
	}

	ca.delegates = []*cryptossh.PublicKey{}

	if len(delegates) > 0 {
		ca.delegates, err = loadDelegates(delegates)
		if err != nil {
			return nil, fmt.Errorf("unable to load delegates, err: %s", err)
		}
	}

	return ca, nil
}
