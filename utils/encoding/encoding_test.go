package encoding_test

import (
	"bytes"
	"cryptopals/utils/encoding"
	"io"
	"strings"
	"testing"
)

func TestHexEncoder(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		encoding encoding.HexEncoding
		output   string
	}{
		{
			name:     "Uppercase",
			input:    []byte{0x01, 0x02, 0x03, 0x00, 0xa0, 0xb0, 0xc0},
			encoding: encoding.UPPERCASE,
			output:   "01020300A0B0C0",
		},
		{
			name:     "Lowercase",
			input:    []byte{0x01, 0x02, 0x03, 0xff, 0xa0, 0xb0, 0xc0},
			encoding: encoding.LOWERCASE,
			output:   "010203ffa0b0c0",
		},
	}

	for _, c := range cases {
		// loop variable c will be captured by reference, so we shadow it with a new variable also
		// called c
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			iBuffer := bytes.NewBuffer(c.input)
			encoder := encoding.HexEncoder(c.encoding, iBuffer)
			oBuffer := new(strings.Builder)
			_, err := io.Copy(oBuffer, encoder)
			if err != nil {
				t.Errorf("want nil got %v", err)
			}
			if oBuffer.String() != c.output {
				t.Errorf("want %v got %v", c.output, oBuffer.String())
			}
		})
	}
}

func TestHexDecoder(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		output      []byte
		expectError bool
	}{
		{
			name:        "Uppercase",
			input:       "01020300a0b0c0",
			output:      []byte{0x01, 0x02, 0x03, 0x00, 0xa0, 0xb0, 0xc0},
			expectError: false,
		},
		{
			name:        "Lowercase",
			input:       "010203ffa0b0c0",
			output:      []byte{0x01, 0x02, 0x03, 0xff, 0xa0, 0xb0, 0xc0},
			expectError: false,
		},
		{
			name:        "OddChars",
			input:       "010203ffa0b0c",
			expectError: true,
		},
		{
			name:        "InvalidChars",
			input:       "010203ffa0b0cx",
			expectError: true,
		},
	}

	for _, c := range cases {
		// loop variable c will be captured by reference, so we shadow it with a new variable also
		// called c
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			iBuffer := bytes.NewBufferString(c.input)
			decoder := encoding.HexDecoder(iBuffer)
			oBuffer := new(bytes.Buffer)
			_, err := io.Copy(oBuffer, decoder)
			if c.expectError {
				if err == nil {
					t.Errorf("want err got %v, %v", err, oBuffer.Bytes())
				}
			} else {
				if err != nil {
					t.Errorf("want nil got %v", err)
				}
				if !bytes.Equal(oBuffer.Bytes(), c.output) {
					t.Errorf("want %v got %v", c.output, oBuffer.Bytes())
				}
			}
		})
	}
}

func TestBase64Encoder(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		encoding encoding.Base64Encoding
		output   string
	}{
		{
			name:     "0Chars",
			input:    []byte(""),
			encoding: encoding.STANDARD,
			output:   "",
		},
		{
			name:     "1Chars",
			input:    []byte("f"),
			encoding: encoding.STANDARD,
			output:   "Zg==",
		},
		{
			name:     "2Chars",
			input:    []byte("fo"),
			encoding: encoding.STANDARD,
			output:   "Zm8=",
		},
		{
			name:     "3Chars",
			input:    []byte("foo"),
			encoding: encoding.STANDARD,
			output:   "Zm9v",
		},
		{
			name:     "4Chars",
			input:    []byte("foob"),
			encoding: encoding.STANDARD,
			output:   "Zm9vYg==",
		},
		{
			name:     "5Chars",
			input:    []byte("fooba"),
			encoding: encoding.STANDARD,
			output:   "Zm9vYmE=",
		},
		{
			name:     "6Chars",
			input:    []byte("foobar"),
			encoding: encoding.STANDARD,
			output:   "Zm9vYmFy",
		},
		{
			name:     "Standard",
			input:    []byte{0xfb, 0xff, 0xfe},
			encoding: encoding.STANDARD,
			output:   "+//+",
		},
		{
			name:     "URL",
			input:    []byte{0xfb, 0xff, 0xfe},
			encoding: encoding.URL,
			output:   "-__-",
		},
	}

	for _, c := range cases {
		// loop variable c will be captured by reference, so we shadow it with a new variable also
		// called c
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			iBuffer := bytes.NewBuffer(c.input)
			encoder := encoding.Base64Encoder(c.encoding, iBuffer)
			oBuffer := new(strings.Builder)
			_, err := io.Copy(oBuffer, encoder)
			if err != nil {
				t.Errorf("want nil got %v", err)
			}
			if oBuffer.String() != c.output {
				t.Errorf("want %v got %v", c.output, oBuffer.String())
			}
		})
	}
}

func TestBase64Decoder(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		output      []byte
		expectError bool
	}{
		{
			name:        "0Chars",
			input:       "",
			output:      []byte{},
			expectError: false,
		},
		{
			name:        "1Chars",
			input:       "Zg==",
			output:      []byte("f"),
			expectError: false,
		},
		{
			name:        "2Chars",
			input:       "Zm8=",
			output:      []byte("fo"),
			expectError: false,
		},
		{
			name:        "3Chars",
			input:       "Zm9v",
			output:      []byte("foo"),
			expectError: false,
		},
		{
			name:        "4Chars",
			input:       "Zm9vYg==",
			output:      []byte("foob"),
			expectError: false,
		},
		{
			name:        "5Chars",
			input:       "Zm9vYmE=",
			output:      []byte("fooba"),
			expectError: false,
		},
		{
			name:        "6Chars",
			input:       "Zm9vYmFy",
			output:      []byte("foobar"),
			expectError: false,
		},
		{
			name:        "Standard",
			input:       "+//+",
			output:      []byte{0xfb, 0xff, 0xfe},
			expectError: false,
		},
		{
			name:        "URL",
			input:       "-__-",
			output:      []byte{0xfb, 0xff, 0xfe},
			expectError: false,
		},
		{
			name:        "TooMuchPadding",
			input:       "abcda===",
			expectError: true,
		},
		{
			name:        "1ImpliedPadding",
			input:       "Zm9vYg",
			output:      []byte("foob"),
			expectError: false,
		},
		{
			name:        "2ImpliedPadding",
			input:       "Zm9vYmE",
			output:      []byte("fooba"),
			expectError: false,
		},
		{
			name:        "InvalidBase64Chars",
			input:       "Zm9vYmE$",
			expectError: true,
		},
	}

	for _, c := range cases {
		// loop variable c will be captured by reference, so we shadow it with a new variable also
		// called c
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			iBuffer := bytes.NewBufferString(c.input)
			decoder := encoding.Base64Decoder(iBuffer)
			oBuffer := new(bytes.Buffer)
			_, err := io.Copy(oBuffer, decoder)
			if c.expectError {
				if err == nil {
					t.Errorf("want err got %v, %v", err, oBuffer.Bytes())
				}
			} else {
				if err != nil {
					t.Errorf("want nil got %v", err)
				}
				if !bytes.Equal(oBuffer.Bytes(), c.output) {
					t.Errorf("want %v got %v", c.output, oBuffer.Bytes())
				}
			}
		})
	}
}
