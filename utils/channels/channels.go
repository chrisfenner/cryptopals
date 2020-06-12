package channels

import "io"

// A Reader reads an output and error channel.
type Reader struct {
	o <-chan byte
	e <-chan error
}

// NewReader creates a new reader pointed at the given data and error channels.
func NewReader(o <-chan byte, e <-chan error) *Reader {
	return &Reader{o, e}
}

// Read reads from the ChannelReader.
func (r *Reader) Read(data []byte) (int, error) {
	for i := range data {
		select {
		case data[i] = <-r.o:
		case err, ok := <-r.e:
			if !ok {
				err = io.EOF
			}
			return i, err
		}
	}
	return len(data), nil
}
