package main

import (
	"crypto/sha256"
	"fmt"
)

func SHA256UsingLibs(message []byte) [32]byte {
	return sha256.Sum256(message)
}

func SHA256(message []byte) [32]byte {
	return sha256.Sum256(message)
}

func main() {
	message := []byte("Ruan Cardozo")
	hash := SHA256(message)
	fmt.Printf("Hash SHA-256 (manual): %x\n", hash)
}