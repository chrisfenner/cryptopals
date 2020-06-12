package main

import (
	"bytes"
	"cryptopals/utils/encoding"
	"fmt"
	"io"
	"os"
)

const (
	input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
)

func main() {
	iBuf := bytes.NewBufferString(input)
	hexDec := encoding.HexDecoder(iBuf)
	b64Enc := encoding.Base64Encoder(encoding.STANDARD, hexDec)

	fmt.Printf("Output:\n")
	io.Copy(os.Stdout, b64Enc)
	fmt.Printf("\n")
}
