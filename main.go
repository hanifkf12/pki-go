package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
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

func sign(data []byte) []byte {
	bytes, err := os.ReadFile("private-new.key")
	if err != nil {
		return nil
	}
	pubKeyBlock, _ := pem.Decode(bytes)
	if pubKeyBlock == nil {
		log.Fatal("Failed to decode private key")
	}
	key, err := x509.ParsePKCS1PrivateKey(pubKeyBlock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse public key: %v", err)
	}

	hashMessage := sha256.Sum256(data)
	//pubKey := key.(*rsa.PublicKey)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashMessage[:])
	if err != nil {
		log.Fatal(err)
	}
	return signature
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

func verify(data []byte, signature []byte) bool {
	bytes, err := os.ReadFile("public-new.key")
	if err != nil {
		log.Println(err)
		return false
	}
	privKeyBlock, _ := pem.Decode(bytes)
	if privKeyBlock == nil {
		log.Fatal("failed pem decode")
	}
	pubKey, err := x509.ParsePKCS1PublicKey(privKeyBlock.Bytes)
	if err != nil {
		log.Fatal("parse public kecy, ", err)
	}

	hashedData := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashedData[:], signature)
	if err != nil {
		log.Println(err)
		return false
	}
	return true
}

func main() {

	//sign data
	signature := sign([]byte("halo"))
	verified := verify([]byte("halo"), signature)
	fmt.Println(verified)

	//encryptdata
	//encrypted := encrypt("hanif")
	//os.WriteFile("test.txt", encrypted, 0666)
	//finalEncryption := base64.StdEncoding.EncodeToString(encrypted)
	//fmt.Println(finalEncryption)
	//
	//decodeString, err := base64.StdEncoding.DecodeString(finalEncryption)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//decrypted := decrypt(decodeString)
	//fmt.Println(string(decrypted))
}
