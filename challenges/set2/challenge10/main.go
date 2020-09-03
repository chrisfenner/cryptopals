package main

import (
	"bytes"
	"cryptopals/utils/aes"
	"cryptopals/utils/encoding"
	"fmt"
	"io"
	"os"
)

const (
	inputFile = "10.txt"
)

func main() {
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("error opening file: %v\n", err)
		return
	}
	defer file.Close()

	decoder := encoding.Base64Decoder(file)
	inputData := bytes.NewBuffer([]byte{})
	_, err = io.Copy(inputData, decoder)
	if err != nil {
		fmt.Printf("error decoding base64 data: %v\n", err)
		return
	}

	var keyBytes [16]byte
	copy(keyBytes[:], []byte("YELLOW SUBMARINE"))
	key := aes.NewKey128(keyBytes)

	var iv [16]byte
	decryptor := aes.Cbc(key, iv, false, inputData)
	decryptedData := bytes.NewBuffer([]byte{})
	_, err = io.Copy(decryptedData, decryptor)
	if err != nil {
		fmt.Printf("error decrypting data: %v\n", err)
		return
	}

	io.Copy(os.Stdout, decryptedData)
}
