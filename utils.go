package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"regexp"
)

func addrToPort(addr string) (int, error) {
	tcpAddr, err := net.ResolveTCPAddr("", addr)
	if err != nil {
		return 0, err
	}

	return tcpAddr.Port, nil
}
func generateSshCommand(user string, host string, port int, command string, identityFilePath string) string {

	strPort := fmt.Sprintf("-p %d", port)
	strIdentityFilePath := fmt.Sprintf("-i %s", identityFilePath)

	if port == 22 {
		strPort = ""
	}
	if identityFilePath == "~/.ssh/id_rsa" {
		strIdentityFilePath = ""
	}

	return regexp.MustCompile(`\s+`).ReplaceAllString(fmt.Sprintf("ssh %s %s %s@%s '%s'", strIdentityFilePath, strPort, user, host, command), " ")
}
func expectedIdentityFilePath(keyFormat string) string {

	switch keyFormat {
	case "ssh-rsa":
		return "~/.ssh/id_rsa"
	case "ssh-ed25519":
		return "~/.ssh/id_ed25519"
	case "ecdsa-sha2-nistp256":
		return "~/.ssh/id_ecdsa"
	}

	return ""
}

func jsonMarshalUnmarshal[T any](value any, target *T) error {
	inrec, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(inrec, target); err != nil {
		return err
	}
	return nil
}

func stringSliceToBytes(target []string) [][]byte {
	l := [][]byte{}
	for _, v := range target {
		l = append(l, []byte(v))
	}
	return l
}

func generatePrivateKey(bitSize int) ([]byte, error) {

	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	d := pem.EncodeToMemory(&pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return d, nil
}
