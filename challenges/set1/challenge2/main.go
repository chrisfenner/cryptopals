package main

import (
	"bytes"
	"cryptopals/utils/encoding"
	"cryptopals/utils/xor"
	"fmt"
	"io"
	"os"
)

const (
	input1 = "1c0111001f010100061a024b53535009181c"
	input2 = "686974207468652062756c6c277320657965"
)

func main() {
	iBuf1 := bytes.NewBufferString(input1)
	iBuf2 := bytes.NewBufferString(input2)
	hexDec1 := encoding.HexDecoder(iBuf1)
	hexDec2 := encoding.HexDecoder(iBuf2)
	xorer := xor.Xor(hexDec1, hexDec2)
	hexEnc := encoding.HexEncoder(encoding.LOWERCASE, xorer)

	fmt.Printf("Output:\n")
	io.Copy(os.Stdout, hexEnc)
	fmt.Printf("\n")
}
