package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"testing"
)

func CompareHash(encodedHash string, saltedData []byte) bool {
	decodedHash, err := base64.StdEncoding.DecodeString(encodedHash)
	if err != nil {
		fmt.Println("Error decoding hash:", err)
		return false
	}

	hasher := sha256.New()
	hasher.Write(saltedData)
	comparisonHash := hasher.Sum(nil)

	return subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1
}

func TestHashSalt(t *testing.T) {
	data := []byte("hanif")
	salt := "somesalt"

	// Concatenate the salt with the data
	saltedData := append(data, []byte(salt)...)

	hasher := sha256.New()
	hasher.Write(saltedData)
	result := hasher.Sum(nil)

	// Encode the hash result to base64 string
	encodedHash := base64.StdEncoding.EncodeToString(result)

	fmt.Println("Salted Data:", string(saltedData))
	fmt.Println("Encoded Hash:", encodedHash)

	// Simulate comparing the hash with the salted value
	match := CompareHash(encodedHash, saltedData)
	if match {
		fmt.Println("Hash matches the salted data.")
	} else {
		fmt.Println("Hash does not match the salted data.")
	}
}
func TestHash(t *testing.T) {
	data := []byte("hanif")
	hasher := sha256.New()
	hasher.Write(data)
	result := hasher.Sum(nil)

	tes := base64.StdEncoding.EncodeToString(result)
	fmt.Println(len(data))
	fmt.Println(len(result))
	fmt.Println(tes)
	bytes, err := base64.StdEncoding.DecodeString(tes)
	if err != nil {
		t.Log(err)
	}
	fmt.Println(string(bytes))
}

func TestMD5(t *testing.T) {
	md5 := md5.New()
	md5.Write([]byte("uuuuu"))
	xxx := md5.Sum(nil)
	ll := base64.StdEncoding.EncodeToString(xxx)
	fmt.Println(ll)
	var data string
	fmt.Scanf("haiii", &data)
	fmt.Println(data)
}
