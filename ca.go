package main

import (
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

type CertificateAuthority struct {
	signer     *ssh.Signer
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey

	TrustedIssuers []*ssh.PublicKey
}

func NewCertificateAuthority(privateKeyData []byte, trustedIssuersData [][]byte) (*CertificateAuthority, error) {
	privateKey, err := ssh.ParseRawPrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return nil, err
	}

	certificateAuthority := &CertificateAuthority{
		signer:     &signer,
		publicKey:  &(privateKey.(*rsa.PrivateKey)).PublicKey,
		privateKey: privateKey.(*rsa.PrivateKey),
	}

	trustedIssuers := []*ssh.PublicKey{}
	for _, issuerData := range trustedIssuersData {
		k, _, _, _, err := ssh.ParseAuthorizedKey(issuerData)
		if err != nil {
			return nil, err
		}
		trustedIssuers = append(trustedIssuers, &k)
	}

	certificateAuthority.TrustedIssuers = trustedIssuers

	return certificateAuthority, nil
}
