package padding

import (
	"cryptopals/utils/channels"
	"io"
)

// Pkcs7 implements PKCS#7 padding with the given block size
func Pkcs7(blockSize byte, r io.Reader) io.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which copies data into the channel block by block, padding the last block.
	go func() {
		defer close(e)
		defer close(o)
		padBuf := make([]byte, blockSize)
		for {
			count, err := r.Read(padBuf[:])
			if count != 0 {
				if (byte)(count) < blockSize {
					// last block, pad it
					padValue := blockSize - (byte)(count)
					for i := (byte)(count); i < blockSize; i++ {
						padBuf[i] = padValue
					}
				}
				for _, b := range padBuf {
					o <- b
				}
			}
			if err != nil {
				e <- err
				return
			}
		}
	}()

	return channels.NewReader(o, e)
}
