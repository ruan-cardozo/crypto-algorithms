package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

func rsaEncryptDecryptLib() {
	// Generate RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Erro ao gerar chave privada: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// Example text to encrypt
	text := "Olá"
	fmt.Println("Texto original:", text)

	// Encrypt the text
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, []byte(text), nil)
	if err != nil {
		log.Fatalf("Erro ao criptografar: %v", err)
	}
	encryptedText := base64.StdEncoding.EncodeToString(encryptedBytes)
	fmt.Println("Texto criptografado:", encryptedText)

	// Decrypt the text
	decodedBytes, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		log.Fatalf("Erro ao decodificar texto criptografado: %v", err)
	}
	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, decodedBytes, nil)
	if err != nil {
		log.Fatalf("Erro ao descriptografar: %v", err)
	}
	decryptedText := string(decryptedBytes)
	fmt.Println("Texto descriptografado:", decryptedText)
}

func main() {
	rsaEncryptDecryptLib()
}