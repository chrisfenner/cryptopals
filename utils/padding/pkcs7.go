package padding

import (
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
		count := byte(0)
		buf := []byte{0}
		for {
			c, err := r.Read(buf)
			if err != nil {
				if err == io.EOF {
					// Underlying reader is done. Add the padding and then we are done.
					padCount := blockSize - count
					for i := byte(0); i < padCount; i++ {
						o <- padCount
					}
				}
				e <- err
				return
			}
			if c > 0 {
				o <- buf[0]
				count = (count + 1) % blockSize
			}
		}
	}()

	return channels.NewReader(o, e)
}
