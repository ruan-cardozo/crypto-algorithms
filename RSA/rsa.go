package main

import (
	"fmt"
	"math/big"
	"strings"
)

// Função RSA: criptografia e descriptografia com RSA
func RSA(text string, p, q int64, isPrivateKey bool) string {
	// Geração de chaves públicas e privadas
	n := p * q                          // Módulo
	phi := (p - 1) * (q - 1)            // Função totiente de Euler
	e := selecionarE(phi)               // Chave pública: selecionar e que seja co-primo com phi
	d := calcularD(e, phi)              // Chave privada: inverso multiplicativo de e mod phi
	fmt.Printf("Chave pública (n=%d, e=%d), Chave privada (d=%d)\n", n, e, d)

	// Criptografia
	if !isPrivateKey {
		// Convertendo cada caractere para números e aplicando criptografia
		var resultado []string
		for _, char := range text {
			mensagem := big.NewInt(int64(char)) // Converter caractere para número
			textoCifrado := new(big.Int).Exp(mensagem, big.NewInt(e), big.NewInt(n)) // c = m^e mod n
			resultado = append(resultado, textoCifrado.Text(10))
		}
		return strings.Join(resultado, " ") // Retornar o texto cifrado
	}

	// Descriptografia
	var resultado []string
	numeros := strings.Split(text, " ")
	for _, numStr := range numeros {
		mensagem := big.NewInt(0)
		mensagem.SetString(numStr, 10)
		textoDecifrado := new(big.Int).Exp(mensagem, big.NewInt(d), big.NewInt(n)) // m = c^d mod n
		resultado = append(resultado, string(rune(textoDecifrado.Int64())))
	}
	return strings.Join(resultado, "")
}

// Selecionar e que seja co-primo com phi
func selecionarE(phi int64) int64 {
	e := int64(2) // Iniciar com e = 2
	for mdc(e, phi) != 1 {
		e++
	}
	return e
}

// Calcular o inverso multiplicativo de e mod phi
func calcularD(e, phi int64) int64 {
	d := int64(1)
	for (d*e)%phi != 1 {
		d++
	}
	return d
}

// Função para calcular o MDC (Máximo Divisor Comum) usando o algoritmo de Euclides
func mdc(a, b int64) int64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func main() {
	// Exemplo de uso do RSA
	p := int64(61) // Primo 1
	q := int64(53) // Primo 2

	// Exemplo de criptografia
	text := "Olá"
	fmt.Println("Texto original:", text)
	encrypted := RSA(text, p, q, false) // Criptografar (não usando chave privada)
	fmt.Println("Texto criptografado:", encrypted)

	// Exemplo de descriptografia
	decrypted := RSA(encrypted, p, q, true) // Descriptografar (usando chave privada)
	fmt.Println("Texto descriptografado:", decrypted)
}
