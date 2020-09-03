package padding

import (
	"bytes"
	"cryptopals/utils/channels"
	"io"
)

// Pkcs7 implements PKCS#7 padding with the given block size.
func Pkcs7(blockSize byte, r io.Reader) io.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which copies data into the channel block by block, padding the last block.
	go func() {
		defer close(e)
		defer close(o)
		buf := new(bytes.Buffer)
		_, err := io.Copy(buf, r)
		if err != nil {
			e <- err
			return
		}
		for _, b := range buf.Bytes() {
			o <- b
		}
		padCount := blockSize - (byte(len(buf.Bytes())) % blockSize)
		if padCount == 0 {
			padCount = blockSize
		}
		for i := byte(0); i < padCount; i++ {
			o <- padCount
		}
		e <- io.EOF
	}()

	return channels.NewReader(o, e)
}
