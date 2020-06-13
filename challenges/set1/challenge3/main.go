package main

import (
	"bytes"
	"cryptopals/utils/encoding"
	"cryptopals/utils/scoring/english"
	"cryptopals/utils/xor"
	"fmt"
	"io"
	"sort"
)

const (
	input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
)

type candidate struct {
	text     string
	variance float64
	key      byte
}

func main() {
	decoder := encoding.HexDecoder(bytes.NewBufferString(input))
	inputData := bytes.NewBuffer([]byte{})
	_, err := io.Copy(inputData, decoder)
	if err != nil {
		fmt.Printf("error decoding hex data: %v\n", err)
		return
	}
	data := inputData.Bytes()
	candidates := make([]candidate, 0)

	// Try every single-character XOR key
	for k := 0; k < 256; k++ {
		// Make a new readable buffer with the data
		inputData := bytes.NewBuffer(data)
		c, err := xor.Cipher(inputData, []byte{byte(k)})
		if err != nil {
			fmt.Printf("error creating xor cipher: %v\n", err)
			return
		}

		// "decrypt" the data
		decryptedData := bytes.NewBuffer([]byte{})
		_, err = io.Copy(decryptedData, c)
		if err != nil {
			fmt.Printf("error decrypting data: %v\n", err)
			return
		}

		// Perform letter frequency analysis
		s := string(decryptedData.Bytes())
		v, err := english.Variance(s)
		if err != nil {
			// contained non-printable characters
			continue
		}
		candidates = append(candidates, candidate{s, v, byte(k)})
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].variance < candidates[j].variance
	})
	for _, c := range candidates {
		fmt.Printf("(%q) %s\n", string([]byte{c.key}), c.text)
	}
}
