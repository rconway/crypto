package main

import (
	"crypto/aes"
	"crypto/cipher"
	"log"
)

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
	// if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	// 	panic(err)
	// }

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext
}

func main() {
	log.Println("crypto...")

	key := []byte("1234567890123456")
	data := []byte("abcdefghijklmnop")
	ciphertext := Encrypt(key, data)
	log.Printf("%x\n", ciphertext)
}
