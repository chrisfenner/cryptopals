package main

import (
	"bytes"
	crand "crypto/rand"
	"cryptopals/utils/aes"
	"cryptopals/utils/padding"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"time"
)

var (
	inputSize  = flag.Int("input_size", 48, "how long the test input can be")
	iterations = flag.Int("iterations", 1000, "how many iterations to test")
	verbose    = flag.Bool("verbose", false, "whether to print fun and helpful messages")
	tableFile  = flag.String("table_file", "", "name of the .csv file to write with the results")
	turtles    = flag.Bool("turtles", false, "Use the naive implementation instead of attacking the padding")
)

func randomKey() (*aes.Key128, error) {
	keyBuf := [16]byte{}
	if _, err := crand.Read(keyBuf[:]); err != nil {
		return nil, err
	}
	k := aes.NewKey128(keyBuf)
	return &k, nil
}

func randomBytes(minCount, maxCount int) ([]byte, error) {
	amount := rand.Intn(maxCount-minCount) + minCount
	randos := make([]byte, amount)
	if _, err := crand.Read(randos); err != nil {
		return nil, err
	}
	return randos, nil
}

type mysteryCiphertext struct {
	ciphertext []byte
	isEcb      bool
}

func ebcOrCbcSandwich(input []byte) (*mysteryCiphertext, error) {
	key, err := randomKey()
	if err != nil {
		return nil, err
	}
	header, err := randomBytes(5, 11)
	if err != nil {
		return nil, err
	}
	trailer, err := randomBytes(5, 11)
	if err != nil {
		return nil, err
	}
	iv := [16]byte{}
	if _, err = crand.Read(iv[:]); err != nil {
		return nil, err
	}

	headerReader := bytes.NewReader(header)
	inputReader := bytes.NewReader(input)
	trailerReader := bytes.NewReader(trailer)
	combined := io.MultiReader(headerReader, inputReader, trailerReader)
	if *verbose {
		fmt.Printf("Header / input / trailer: %d / %d / %d\n", len(header), len(input), len(trailer))
	}

	combinedBuf := bytes.NewBuffer(make([]byte, 0))
	if _, err := io.Copy(combinedBuf, combined); err != nil {
		return nil, err
	}

	paddedBuf := bytes.NewBuffer(make([]byte, 0))
	if _, err := io.Copy(paddedBuf, padding.Pkcs7(16, combinedBuf)); err != nil {
		return nil, err
	}
	if *verbose {
		fmt.Printf("Padded buffer: %v\n", paddedBuf.Bytes())
	}

	var encryptor io.Reader
	wasEcb := false
	if rand.Intn(2) == 1 {
		encryptor = aes.Ecb(key, true, paddedBuf)
		wasEcb = true
		if *verbose {
			fmt.Printf("Is ECB\n")
		}
	} else {
		encryptor = aes.Cbc(key, iv, true, paddedBuf)
		if *verbose {
			fmt.Printf("Is CBC\n")
		}
	}
	output := bytes.NewBuffer(make([]byte, 0))
	if _, err = io.Copy(output, encryptor); err != nil {
		return nil, err
	}

	return &mysteryCiphertext{
		ciphertext: output.Bytes(),
		isEcb:      wasEcb,
	}, nil
}

func guessIfEbc(ciphertext []byte) bool {
	blocks := make(map[[16]byte]bool)
	// iterate the cipher text 16 bytes at a time and look for duplicate blocks
	for n := 0; n <= len(ciphertext)-16; n++ {
		block := [16]byte{}
		copy(block[:], ciphertext[n:n+16])
		if blocks[block] {
			// didn't expect to see the same block twice except for ECB mode
			if *verbose {
				fmt.Printf("Guess ECB\n")
			}
			return true
		}
		blocks[block] = true
	}
	if *verbose {
		fmt.Printf("Guess CBC\n")
	}
	return false
}

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	minInputSize := *inputSize
	var file *os.File
	if *tableFile != "" {
		minInputSize = 1
		var err error
		file, err = os.OpenFile(*tableFile, os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening %v for writing: %v\n", *tableFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(file, "input_length,was_ecb_guessed_ecb,was_ecb_guessed_cbc,was_cbc_guessed_ebc,was_cbc_guessed_cbc\n")
		defer file.Close()
	}
	for i := minInputSize; i <= *inputSize; i++ {
		var input []byte
		if *turtles {
			inputString := strings.Repeat("I LIKE TURTLES! ", (i/16)+1)
			input = []byte(inputString[:i])
		} else {
			input = make([]byte, i)
			for j := 0; j < len(input); j++ {
				input[j] = 0x10
			}
		}
		if *verbose {
			if *turtles {
				fmt.Printf("Input: %v\n", string(input))

			} else {
				fmt.Printf("Input: %v\n", input)
			}
		}
		rightEcb, wrongEcb, rightCbc, wrongCbc := 0, 0, 0, 0
		for i := 0; i < *iterations; i++ {
			mc, err := ebcOrCbcSandwich(input)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error generating ciphertext: %v\n", err)
				os.Exit(1)
			}
			guessedEcb := guessIfEbc(mc.ciphertext)
			if mc.isEcb {
				if guessedEcb {
					rightEcb++
				} else {
					wrongEcb++
				}
			} else {
				if guessedEcb {
					wrongCbc++
				} else {
					rightCbc++
				}
			}
		}
		if *tableFile != "" {
			// Add the table row
			fmt.Fprintf(file, "%d,%d,%d,%d,%d\n", i, rightEcb, wrongEcb, wrongCbc, rightCbc)
			fmt.Printf("Wrote table row for input size %d\n", i)
		} else if i == *inputSize {
			// Print the last iteration to stdout
			fmt.Printf("Total iterations: %d\n", *iterations)
			fmt.Printf("Input length: %d\n", *inputSize)
			fmt.Printf("Overall accuracy: %d out of %d (%f%%)\n", rightEcb+rightCbc, *iterations, 100.0*(float64)(rightEcb+rightCbc)/(float64)(*iterations))
			fmt.Printf("Was ECB, Guessed ECB: %d\n", rightEcb)
			fmt.Printf("Was ECB, Guessed CBC: %d\n", wrongEcb)
			fmt.Printf("Was CBC, Guessed ECB: %d\n", wrongCbc)
			fmt.Printf("Was CBC, Guessed CBC: %d\n", rightCbc)
		}

	}

}
