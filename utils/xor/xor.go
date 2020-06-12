package xor

import (
	"cryptopals/utils/channels"
	"fmt"
	"io"
)

// Xor combines two Readers with logical-XOR.
func Xor(r1 io.Reader, r2 io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which decodes data from the reader as bytes on o.
	// If the reader returns io.EOF, the goroutine closes e and o and returns.
	go func() {
		defer close(e)
		defer close(o)
		buf1 := make([]byte, 1)
		buf2 := make([]byte, 1)
		for {
			count1, err1 := r1.Read(buf1)
			count2, err2 := r2.Read(buf2)
			if count1 != count2 {
				e <- fmt.Errorf("buffers not same length")
				return
			}
			if count1 > 0 {
				o <- buf1[0] ^ buf2[0]
			}
			if err1 != nil {
				e <- err1
				return
			}
			if err2 != nil {
				e <- err2
				return
			}
		}
	}()

	return channels.NewReader(o, e)
}
