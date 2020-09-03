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
	iterations = flag.Int("iterations", 10, "how many iterations to test")
	verbose    = flag.Bool("verbose", false, "whether to print fun and helpful messages")
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
	paddedReader := padding.Pkcs7(16, io.MultiReader(headerReader, inputReader, trailerReader))
	if *verbose {
		fmt.Printf("Header / input / trailer: %d / %d / %d\n", len(header), len(input), len(trailer))
	}

	var encryptor io.Reader
	wasEcb := false
	if rand.Intn(2) == 1 {
		encryptor = aes.Ecb(key, true, paddedReader)
		wasEcb = true
		if *verbose {
			fmt.Printf("Is ECB\n")
		}
	} else {
		encryptor = aes.Cbc(key, iv, true, paddedReader)
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
	blocks := make(map[[16]byte]int)
	expectedReps := (*inputSize / 16) - 1
	// iterate the cipher text 16 bytes at a time and look for duplicate blocks
	for n := 0; n < len(ciphertext)/16; n++ {
		block := [16]byte{}
		copy(block[:], ciphertext[16*n:16*n+1])
		if blocks[block] == expectedReps {
			// didn't expect to see the same block twice except for ECB mode
			if *verbose {
				fmt.Printf("Guess ECB\n")
			}
			return true
		}
		blocks[block]++
	}
	if *verbose {
		fmt.Printf("Guess CBC\n")
	}
	return false
}

func main() {
	rand.Seed(time.Now().UnixNano())
	flag.Parse()

	// Always encrypt at least two blocks of controlled message.
	if *inputSize < 32 {
		fmt.Fprintf(os.Stderr, "Please specify input_size of at least 16 (one block)\n")
		os.Exit(1)
	}
	inputString := strings.Repeat("I LIKE TURTLES! ", (*inputSize/16)+1)
	inputString = inputString[:*inputSize]
	if *verbose {
		fmt.Printf("Input string: %v\n", inputString)
	}
	rightEcb, wrongEcb, rightCbc, wrongCbc := 0, 0, 0, 0
	for i := 0; i < *iterations; i++ {
		mc, err := ebcOrCbcSandwich([]byte(inputString))
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
	fmt.Printf("Total iterations: %d\n", *iterations)
	fmt.Printf("Input length: %d\n", *inputSize)
	fmt.Printf("Overall accuracy: %d out of %d (%f%%)\n", rightEcb+rightCbc, *iterations, 100.0*(float64)(rightEcb+rightCbc)/(float64)(*iterations))
	fmt.Printf("Was ECB, Guessed ECB: %d\n", rightEcb)
	fmt.Printf("Was ECB, Guessed CBC: %d\n", wrongEcb)
	fmt.Printf("Was CBC, Guessed ECB: %d\n", wrongCbc)
	fmt.Printf("Was CBC, Guessed CBC: %d\n", rightCbc)
}
