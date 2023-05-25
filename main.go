package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func encrypt(data string) []byte {
	bytes, err := os.ReadFile("pub_key.key")
	if err != nil {
		return nil
	}
	pubKeyBlock, _ := pem.Decode(bytes)
	if pubKeyBlock == nil {
		log.Fatal("Failed to decode private key")
	}
	key, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}
	pubKey := key.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, []byte(data), nil)
	if err != nil {
		return nil
	}
	return cipherText
}

func sign(data string) []byte {
	bytes, err := os.ReadFile("public-new.key")
	if err != nil {
		return nil
	}
	pubKeyBlock, _ := pem.Decode(bytes)
	if pubKeyBlock == nil {
		log.Fatal("Failed to decode private key")
	}
	key, err := x509.ParsePKCS1PublicKey(pubKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}
	//pubKey := key.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(data))
	if err != nil {
		return nil
	}
	return cipherText
}

func decrypt(data []byte) []byte {
	bytes, err := os.ReadFile("priv_key.key")
	if err != nil {
		return nil
	}
	privKeyBlock, _ := pem.Decode(bytes)
	if privKeyBlock == nil {
		log.Fatal("failed pem decode")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}
	oaep, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
	if err != nil {
		log.Fatal(err)
	}
	return oaep
}

func verify(data []byte) []byte {
	bytes, err := os.ReadFile("private-new.key")
	if err != nil {
		return nil
	}
	privKeyBlock, _ := pem.Decode(bytes)
	if privKeyBlock == nil {
		log.Fatal("failed pem decode")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privKeyBlock.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	oaep, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, data)
	if err != nil {
		log.Fatal("sss", err)
	}
	return oaep
}

func main() {
	encrypted := encrypt("hanif")
	//os.WriteFile("test.txt", encrypted, 0666)

	//signed := sign("halo")
	//fmt.Println(string(signed))
	//verified := verify(signed)
	//fmt.Println(string(verified))

	finalEncryption := base64.StdEncoding.EncodeToString(encrypted)
	fmt.Println(finalEncryption)

	decodeString, err := base64.StdEncoding.DecodeString(finalEncryption)
	if err != nil {
		log.Fatal(err)
	}
	decrypted := decrypt(decodeString)
	fmt.Println(string(decrypted))
}
