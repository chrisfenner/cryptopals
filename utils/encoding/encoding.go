package encoding

import (
	"cryptopals/utils/channels"
	"fmt"
	"io"
)

// HexEncoding represents a mode for hex encoding.
type HexEncoding int

const (
	// UPPERCASE hex encoding uses all uppercase letters.
	UPPERCASE HexEncoding = iota
	// LOWERCASE hex encoding uses all lowercase letters.
	LOWERCASE
)

// hexEncodeNybble encodes a single nybble of hex.
// in MUST be a value between 0 and 15
// enc MUST be a valid HexEncoding
func hexEncodeNybble(in byte, enc HexEncoding) byte {
	switch {
	case in >= 0 && in <= 9:
		return byte('0') + in
	case in >= 0xa && in <= 0xf:
		var a byte
		switch enc {
		case UPPERCASE:
			a = 'A'
		case LOWERCASE:
			a = 'a'
		default:
			panic("invalid hex encoding")
		}
		return byte(a) + (in - 10)
	default:
		panic("invalid nybble value")
	}
}

// HexEncoder creates a HexEncoder with the specified encoding that reads from a Reader.
func HexEncoder(enc HexEncoding, r io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which encodes data from the reader as hex characters on o.
	// If the reader returns io.EOF, the goroutine closes e and o and returns.
	go func() {
		defer close(e)
		defer close(o)
		buf := make([]byte, 1)
		for {
			count, err := r.Read(buf)
			if count != 0 {
				o <- hexEncodeNybble(buf[0]>>4, enc)
				o <- hexEncodeNybble(buf[0]&0xf, enc)
			}
			if err != nil {
				e <- err
				return
			}
		}
	}()

	return channels.NewReader(o, e)
}

// hexDecodeNybble decodes a single nybble of hex.
func hexDecodeNybble(in byte) (byte, error) {
	switch {
	case in >= '0' && in <= '9':
		return in - '0', nil
	case in >= 'a' && in <= 'f':
		return (in - 'a') + 10, nil
	case in >= 'A' && in <= 'F':
		return (in - 'A') + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character %q", rune(in))
	}
}

// HexDecoder creates a HexDecoder that reads from a Reader.
func HexDecoder(r io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which decodes data from the reader as bytes on o.
	// If the reader returns io.EOF, the goroutine closes e and o and returns.
	go func() {
		defer close(e)
		defer close(o)
		buf := make([]byte, 2)
		for {
			count, err := r.Read(buf)
			switch count {
			case 2:
				high, decErr := hexDecodeNybble(buf[0])
				if decErr != nil {
					e <- decErr
					return
				}
				low, decErr := hexDecodeNybble(buf[1])
				if decErr != nil {
					e <- decErr
					return
				}
				o <- (high << 4) + low
			case 1:
				e <- fmt.Errorf("odd number of hex characters detected")
				return
			}
			if err != nil {
				e <- err
				return
			}
		}
	}()

	return channels.NewReader(o, e)
}

// Base64Encoding represents a mode for base64 encoding
type Base64Encoding int

const (
	// STANDARD uses + and / for code points 62 and 63, respectively
	STANDARD Base64Encoding = iota
	// URL uses - and _ for code points 62 and 63, respectively
	URL
)

// base64EncodeHextet encodes a single hextet of base64
// in MUST be 0 to 63, or 255 (replace with padding marker)
// enc MUST be a valid Base64Encoding
func base64EncodeHextet(in byte, enc Base64Encoding) byte {
	switch {
	case in == 255:
		return '='
	case in >= 0 && in <= 25:
		return 'A' + in
	case in >= 26 && in <= 51:
		return 'a' + (in - 26)
	case in >= 52 && in <= 61:
		return '0' + (in - 52)
	case in == 62:
		switch enc {
		case STANDARD:
			return '+'
		case URL:
			return '-'
		default:
			panic("invalid base64 encoding")
		}
	case in == 63:
		switch enc {
		case STANDARD:
			return '/'
		case URL:
			return '_'
		default:
			panic("invalid base64 encoding")
		}
	default:
		panic(fmt.Sprintf("invalid hextet value %v", in))
	}
}

// base64Encode3Bytes encodes up to 3 bytes from in as a set of 4 ASCII base64 characters according
// to enc.
// in MUST be between 1 and 3 bytes
// enc MUST be a valid Base64Encoding
func base64Encode3Bytes(in []byte, enc Base64Encoding) [4]byte {
	if len(in) < 1 || len(in) > 3 {
		panic("invalid length byte slice for base64 encode")
	}

	// capture the hextets in an array for returning and encode them in place
	r := [4]byte{255, 255, 255, 255}
	r[0] = in[0] >> 2
	r[1] = (in[0] & 0x03) << 4
	if len(in) >= 2 {
		r[1] += in[1] >> 4
		r[2] = (in[1] & 0x0f) << 2
	}
	if len(in) == 3 {
		r[2] += in[2] >> 6
		r[3] = in[2] & 0x3f
	}

	for i := range r {
		r[i] = base64EncodeHextet(r[i], enc)
	}
	return r
}

// Base64Encoder creates a Base64Encoder with the specified encoding that reads from a Reader.
func Base64Encoder(enc Base64Encoding, r io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which decodes data from the reader as bytes on o.
	// If the reader returns io.EOF, the goroutine closes e and o and returns.
	go func() {
		defer close(e)
		defer close(o)
		buf := make([]byte, 3)
		for {
			count, err := r.Read(buf)
			if count > 0 {
				encoded := base64Encode3Bytes(buf[:count], enc)
				for _, c := range encoded {
					o <- c
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

// base64DecodeHextet decodes a single hextet of base64
func base64DecodeHextet(in byte) (byte, error) {
	switch {
	case in >= 'A' && in <= 'Z':
		return in - 'A', nil
	case in >= 'a' && in <= 'z':
		return (in - 'a') + 26, nil
	case in >= '0' && in <= '9':
		return (in - '0') + 52, nil
	case in == '+' || in == '-':
		return 62, nil
	case in == '/' || in == '_':
		return 63, nil
	default:
		return 0, fmt.Errorf("invalid base64 character %v", in)
	}
}

// base64Decode4Chars decode up to 4 ASCII base64 characters from in as a set of up to 3 bytes.
// in MUST be btween 2 and 4 bytes
func base64Decode4Chars(in []byte) ([]byte, error) {
	if len(in) < 2 || len(in) > 4 {
		panic("invalid length byte slice for base64 decode")
	}

	// count the padding characters backwards from the end of in
	padding := 0
	for i := len(in) - 1; i >= 0; i-- {
		if in[i] != '=' {
			break
		}
		padding++
	}
	// there should be no padding characters before the contiguous region of padding
	for i := 0; i < len(in)-padding-1; i++ {
		if in[i] == '=' {
			return nil, fmt.Errorf("invalid padding sequence %q", string(in))
		}
	}
	// add pretend padding if we got less than 4 bytes
	if len(in) < 4 {
		padding += (4 - len(in))
	}
	// there must not be more than 2 padding, real or pretend
	if padding > 2 {
		return nil, fmt.Errorf("incomplete base64 sequence: %q", string(in))
	}

	r := [3]byte{}
	var w, x, y, z byte // hold the hextets decoded from in
	w, err := base64DecodeHextet(in[0])
	if err != nil {
		return nil, err
	}
	x, err = base64DecodeHextet(in[1])
	r[0] = w<<2 + (x >> 4)
	if padding < 2 {
		r[1] = (x & 0x0f) << 4
		y, err = base64DecodeHextet(in[2])
		if err != nil {
			return nil, err
		}
		r[1] += y >> 2
	}
	if padding < 1 {
		r[2] = (y & 0x03) << 6
		z, err = base64DecodeHextet(in[3])
		if err != nil {
			return nil, err
		}
		r[2] += z
	}

	return r[:3-padding], nil
}

// Base64Decoder creates a Base64Decoder that reads from a Reader.
func Base64Decoder(r io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which decodes data from the reader as bytes on o.
	// If the reader returns io.EOF, the goroutine closes e and o and returns.
	go func() {
		defer close(e)
		defer close(o)
		buf := make([]byte, 4)
		for {
			count, err := r.Read(buf)
			if count > 0 {
				decoded, err := base64Decode4Chars(buf[:count])
				if err != nil {
					e <- err
					return
				}
				for _, c := range decoded {
					o <- c
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
