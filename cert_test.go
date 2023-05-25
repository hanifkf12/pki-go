package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
)

func TestName(t *testing.T) {
	bits := 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	privateKeyPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}))
	err = os.WriteFile("private-new.key", []byte(privateKeyPem), 0666)
	if err != nil {
		t.Log(err)
	}

	publicKeyPem := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	}))
	err = os.WriteFile("public-new.key", []byte(publicKeyPem), 0666)
	if err != nil {
		t.Log(err)
	}
}
