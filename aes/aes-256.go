package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Função para criptografar o texto
func encrypt(text, key string) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	plaintext := []byte(text)
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return hex.EncodeToString(ciphertext), nil
}

// Função para descriptografar o texto
func decrypt(encryptedText, key string) (string, error) {
	ciphertext, err := hex.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return string(ciphertext), nil
}

func main() {
	text := "Esta é uma mensagem secreta que precisa ser criptografada com AES."
	key := "chavede16bytes!!chavede16bytes!!" // 32 bytes para AES-256

	encrypted, err := encrypt(text, key)
	if err != nil {
		fmt.Println("Erro ao criptografar:", err)
		return
	}

	fmt.Println("Texto original:", text)
	fmt.Println("Texto criptografado:", encrypted)

	decrypted, err := decrypt(encrypted, key)
	if err != nil {
		fmt.Println("Erro ao descriptografar:", err)
		return
	}

	fmt.Println("Texto descriptografado:", decrypted)
}
