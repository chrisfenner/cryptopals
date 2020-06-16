package main

import (
	"bufio"
	"bytes"
	"cryptopals/utils/encoding"
	"cryptopals/utils/scoring/english"
	"cryptopals/utils/xor"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	inputFile = "4.txt"
)

type candidate struct {
	text       string
	variance   float64
	key        byte
	lineNumber int
}

func clean(dirty []byte) string {
	var result strings.Builder
	for i, b := range dirty {
		if (b >= 0x20 && b <= 0x7e) || b == ' ' {
			result.Write(dirty[i : i+1])
		} else {
			fmt.Fprintf(&result, "<0x%x>", b)
		}
	}
	return result.String()
}

func main() {
	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("error opening file: %v\n", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	candidates := make([]candidate, 0)

	// Try every line in the file
	line := 0
	for scanner.Scan() {
		line++
		buffer := bytes.NewBufferString(scanner.Text())
		decoder := encoding.HexDecoder(buffer)
		inputData := bytes.NewBuffer([]byte{})
		_, err := io.Copy(inputData, decoder)
		if err != nil {
			fmt.Printf("error decoding hex data: %v\n", err)
			return
		}
		data := inputData.Bytes()

		// Try every single-character XOR key
		for k := 0; k < 256; k++ {
			// Make a new readable buffer with the data
			d2 := make([]byte, len(data))
			copy(d2, data)
			inputData := bytes.NewBuffer(d2)

			// Set up the xor cipher with k as the single-character key.
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
				// fmt.Printf("error analyzing data: %v\n", err)
				// continue
			}
			candidates = append(candidates, candidate{s, v, byte(k), line})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].variance < candidates[j].variance
	})
	for _, c := range candidates {
		fmt.Printf("%v: (%q) [%v] %s\n", c.lineNumber, string([]byte{c.key}), c.variance, clean([]byte(c.text)))
	}
}
