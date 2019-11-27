package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// GenerateKey generates a key (random bytes) of the specified size (bits)
func GenerateKey(key []byte) {
	sizeBytes := len(key)
	log.Printf("Generating key of size %v bits => %v bytes\n", (sizeBytes * 8), sizeBytes)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	log.Printf("Key generated => %x\n", key)
}

// Encrypt encrypt 'plaintext' using 'key' (AES CBC)
func Encrypt(key []byte, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Random IV...
	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func main() {
	log.Println("crypto...")

	// Generate key
	const KeySizeBits = 128
	key := make([]byte, KeySizeBits/8)
	GenerateKey(key)

	// Encrypt data
	data := []byte("abcdefghijklmnop")
	ciphertext := Encrypt(key, data)
	log.Printf("Ciphertext => %x\n", ciphertext)
}
