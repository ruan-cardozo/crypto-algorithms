package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Constantes iniciais de hash para SHA-256
var h = [8]uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// Constantes de rotação do SHA-256 (tabeladas)
var k = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

// Função principal SHA-256
func SHA256(message []byte) [32]byte {
	// Passo 1: Adicionar padding
	message = adicionarPadding(message)

	// Passo 2: Dividir a mensagem em blocos de 512 bits
	blocos := dividirEmBlocos(message)

	// Passo 3: Inicializar os hashes (os valores de 'h' já estão definidos)
	hAtual := h

	// Processamento de cada bloco de 512 bits
	for _, bloco := range blocos {
		// Expansão do bloco de 512 bits para 64 palavras de 32 bits
		w := expandirBloco(bloco)

		// Guardar os valores atuais de hash
		a, b, c, d, e, f, g, h := hAtual[0], hAtual[1], hAtual[2], hAtual[3], hAtual[4], hAtual[5], hAtual[6], hAtual[7]

		// Compressão principal do SHA-256
		for i := 0; i < 64; i++ {
			t1 := h + sigma1(e) + ch(e, f, g) + k[i] + w[i]
			t2 := sigma0(a) + maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}

		// Atualizar os valores do hash com os valores comprimidos
		hAtual[0] += a
		hAtual[1] += b
		hAtual[2] += c
		hAtual[3] += d
		hAtual[4] += e
		hAtual[5] += f
		hAtual[6] += g
		hAtual[7] += h
	}

	// Gerar o hash final
	var hash [32]byte
	for i, valor := range hAtual {
		binary.BigEndian.PutUint32(hash[i*4:], valor)
	}
	return hash
}

// Função para adicionar padding à mensagem (passo 1)
func adicionarPadding(message []byte) []byte {
	originalLen := len(message) * 8
	message = append(message, 0x80) // Adicionar o bit '1'

	// Adicionar bits '0' até que o comprimento seja congruente a 448 mod 512
	for len(message)%64 != 56 {
		message = append(message, 0x00)
	}

	// Adicionar o comprimento original da mensagem como inteiro de 64 bits
	var tamanho [8]byte
	binary.BigEndian.PutUint64(tamanho[:], uint64(originalLen))
	message = append(message, tamanho[:]...)

	return message
}

// Função para dividir a mensagem em blocos de 512 bits (passo 2)
func dividirEmBlocos(message []byte) [][]byte {
	var blocos [][]byte
	for i := 0; i < len(message); i += 64 {
		blocos = append(blocos, message[i:i+64])
	}
	return blocos
}

// Função para expandir o bloco de 512 bits para 64 palavras de 32 bits (passo 3)
func expandirBloco(bloco []byte) [64]uint32 {
	var w [64]uint32

	// Copiar os primeiros 16 valores do bloco para w
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(bloco[i*4:])
	}

	// Expandir os valores restantes
	for i := 16; i < 64; i++ {
		s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
		s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}

	return w
}

// Funções auxiliares do SHA-256
func ch(x, y, z uint32) uint32   { return (x & y) ^ (^x & z) }
func maj(x, y, z uint32) uint32  { return (x & y) ^ (x & z) ^ (y & z) }
func sigma0(x uint32) uint32     { return bits.RotateLeft32(x, -2) ^ bits.RotateLeft32(x, -13) ^ bits.RotateLeft32(x, -22) }
func sigma1(x uint32) uint32     { return bits.RotateLeft32(x, -6) ^ bits.RotateLeft32(x, -11) ^ bits.RotateLeft32(x, -25) }

func main() {
	message := []byte("Ruan Cardozo")
	hash := SHA256(message)
	fmt.Printf("Hash SHA-256: %x\n", hash)
}
