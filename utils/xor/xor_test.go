package xor_test

import (
	"bytes"
	"cryptopals/utils/xor"
	"io"
	"testing"
)

func TestXor(t *testing.T) {
	cases := []struct {
		name        string
		input1      []byte
		input2      []byte
		output      []byte
		expectError bool
	}{
		{
			name:        "Ok",
			input1:      []byte{0x01, 0x02, 0x03, 0x00, 0x04},
			input2:      []byte{0x10, 0x20, 0x01, 0x01, 0x04},
			output:      []byte{0x11, 0x22, 0x02, 0x01, 000},
			expectError: false,
		},
		{
			name:        "MismatchedSizes",
			input1:      []byte{0x01, 0x02, 0x03, 0x00, 0x04},
			input2:      []byte{0x10, 0x20, 0x01, 0x01},
			expectError: true,
		},
	}

	for _, c := range cases {
		// loop variable c will be captured by reference, so we shadow it with a new variable also
		// called c
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			iBuffer1 := bytes.NewBuffer(c.input1)
			iBuffer2 := bytes.NewBuffer(c.input2)
			xorer := xor.Xor(iBuffer1, iBuffer2)
			oBuffer := new(bytes.Buffer)
			_, err := io.Copy(oBuffer, xorer)
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
