package aes

import (
	"bytes"
	"cryptopals/utils/channels"
	"fmt"
	"io"
)

var sboxEnc = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

var sboxDec = [256]byte{
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
}

// Key encapsulates an AES key of any size.
type Key interface {
	// Returns a channel which first gets the initial round key, then all the following round keys.
	KeySchedule() chan [16]byte
}

// Key128 represents an AES-128 key.
type Key128 struct {
	data [16]byte
}

// NewKey128 creates an AES-128 key with the given data.
func NewKey128(data [16]byte) Key128 {
	return Key128{data: data}
}

func makeKey(w [4]uint32) [16]byte {
	var r [16]byte
	for i := 0; i < 16; i++ {
		r[i] = (byte)(w[i/4] >> (8 * (3 - (i % 4))) & 0xff)
	}
	return r
}

func subWord(w uint32) uint32 {
	var r uint32

	for i := 0; i < 4; i++ {
		r += (uint32)(sboxEnc[(byte)(w)]) << (8 * i)
		w >>= 8
	}

	return r
}

func rotWord(w uint32) uint32 {
	return w<<8 + w>>24
}

// KeySchedule returns the key schedule for an AES-128 key.
func (k Key128) KeySchedule() chan [16]byte {
	s := make(chan [16]byte)
	go func() {
		var w [4]uint32
		for i := 0; i < 16; i++ {
			w[i/4] <<= 8
			w[i/4] += (uint32)(k.data[i])
		}
		s <- makeKey(w)
		rc := (byte)(0x01)
		for i := 0; i < 10; i++ {
			var w2 [4]uint32
			w2[0] = w[0] ^ subWord(rotWord(w[3])) ^ ((uint32)(rc) << 24)
			w2[1] = w[1] ^ w2[0]
			w2[2] = w[2] ^ w2[1]
			w2[3] = w[3] ^ w2[2]

			s <- makeKey(w2)

			t := rc&0x80 != 0
			rc <<= 1
			if t {
				rc ^= 0x1b
			}
			w = w2
		}
		close(s)
	}()

	return s
}

// AddRoundKey adds the given round key into the state.
func AddRoundKey(state *[16]byte, roundKey *[16]byte) {
	for i := 0; i < 16; i++ {
		state[i] ^= roundKey[i]
	}
}

// SubBytes looks up the data in the lookup table according to the AES s-box.
func SubBytes(state *[16]byte, encrypt bool) {
	for i := 0; i < 16; i++ {
		if encrypt {
			state[i] = sboxEnc[state[i]]
		} else {
			state[i] = sboxDec[state[i]]
		}
	}
}

// ShiftRows performs the 'ShiftRows' step of the Rijndael cipher.
func ShiftRows(s *[16]byte, encrypt bool) {
	if encrypt {
		*s = [16]byte{
			s[0], s[5], s[10], s[15],
			s[4], s[9], s[14], s[3],
			s[8], s[13], s[2], s[7],
			s[12], s[1], s[6], s[11]}
	} else {
		*s = [16]byte{
			s[0], s[13], s[10], s[7],
			s[4], s[1], s[14], s[11],
			s[8], s[5], s[2], s[15],
			s[12], s[9], s[6], s[3]}
	}
}

// gfmult multiplies the two given values under GF(2^8)
func gfmult(a, b byte) byte {
	var r byte
	for a > 0 {
		if a&0x01 != 0 {
			r ^= b
		}
		t := b&0x80 != 0
		b <<= 1
		if t {
			b ^= 0x1b
		}
		a >>= 1
	}
	return r
}

func mixColumn(c [4]*byte, encrypt bool) {
	var temp [4]byte
	for i := 0; i < 4; i++ {
		temp[i] = *c[i]
	}

	if encrypt {
		*c[0] = gfmult((byte)(2), temp[0]) ^ gfmult((byte)(3), temp[1]) ^ temp[2] ^ temp[3]
		*c[1] = temp[0] ^ gfmult((byte)(2), temp[1]) ^ gfmult((byte)(3), temp[2]) ^ temp[3]
		*c[2] = temp[0] ^ temp[1] ^ gfmult((byte)(2), temp[2]) ^ gfmult((byte)(3), temp[3])
		*c[3] = gfmult((byte)(3), temp[0]) ^ temp[1] ^ temp[2] ^ gfmult((byte)(2), temp[3])
	} else {
		*c[0] = gfmult((byte)(14), temp[0]) ^ gfmult((byte)(11), temp[1]) ^ gfmult((byte)(13), temp[2]) ^ gfmult((byte)(9), temp[3])
		*c[1] = gfmult((byte)(9), temp[0]) ^ gfmult((byte)(14), temp[1]) ^ gfmult((byte)(11), temp[2]) ^ gfmult((byte)(13), temp[3])
		*c[2] = gfmult((byte)(13), temp[0]) ^ gfmult((byte)(9), temp[1]) ^ gfmult((byte)(14), temp[2]) ^ gfmult((byte)(11), temp[3])
		*c[3] = gfmult((byte)(11), temp[0]) ^ gfmult((byte)(13), temp[1]) ^ gfmult((byte)(9), temp[2]) ^ gfmult((byte)(14), temp[3])
	}
}

// MixColumns performs the 'MixColumns' step of the Rijndael cipher.
func MixColumns(state *[16]byte, encrypt bool) {
	mixColumn([4]*byte{&state[0], &state[1], &state[2], &state[3]}, encrypt)
	mixColumn([4]*byte{&state[4], &state[5], &state[6], &state[7]}, encrypt)
	mixColumn([4]*byte{&state[8], &state[9], &state[10], &state[11]}, encrypt)
	mixColumn([4]*byte{&state[12], &state[13], &state[14], &state[15]}, encrypt)
}

func reverse(c chan [16]byte) chan [16]byte {
	r := make(chan [16]byte)

	go func() {
		stack := make([][16]byte, 0)
		for x := range c {
			stack = append(stack, x)
		}
		for i := len(stack) - 1; i >= 0; i-- {
			r <- stack[i]
		}
		close(r)
	}()

	return r
}

// Rijndael performs a raw AES operation on a single block of data.
func Rijndael(key Key, encrypt bool, data [16]byte) (*[16]byte, error) {
	state := data
	var schedule chan [16]byte
	if encrypt {
		schedule = key.KeySchedule()
	} else {
		schedule = reverse(key.KeySchedule())
	}
	firstRoundKey, ok := <-schedule
	if !ok {
		return nil, fmt.Errorf("key had empty key schedule")
	}

	AddRoundKey(&state, &firstRoundKey)

	if encrypt {
		if roundKey, ok := <-schedule; ok {
			for {
				nextRoundKey, ok := <-schedule
				finalRound := !ok

				SubBytes(&state, true)
				ShiftRows(&state, true)
				if !finalRound {
					MixColumns(&state, true)
				}
				AddRoundKey(&state, &roundKey)

				if finalRound {
					break
				}

				roundKey = nextRoundKey
			}
		}
	} else {
		firstRound := true
		for roundKey := range schedule {
			if !firstRound {
				MixColumns(&state, false)
			}
			ShiftRows(&state, false)
			SubBytes(&state, false)
			AddRoundKey(&state, &roundKey)

			firstRound = false
		}
	}

	return &state, nil
}

// Ecb creates an AES-ECB encryption/decryption engine (depends on the value of `encrypt`) using the
// supplied key.
func Ecb(key Key, encrypt bool, r io.Reader) *channels.Reader {
	o := make(chan byte)
	e := make(chan error)

	// Create a goroutine which encrypts/decrypts data block by block.
	go func() {
		defer close(e)
		defer close(o)
		var buf [16]byte
		for {
			count, err := r.Read(buf[:])
			if count != 0 {
				if count < 16 {
					e <- fmt.Errorf("padding not supported - supply a multiple of 16 bytes of data")
					return
				}
				output, err := Rijndael(key, encrypt, buf)
				if err != nil {
					e <- err
					return
				}
				for _, b := range output {
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

// Cbc creates an AES-CBC encryption/decryption engine (depends on the value of `encrypt`) using the
// supplied key.
// TODO: Make this fancy-elegant by building it out of ECB with some stuff from the io package
// (without introducing deadlock)
func Cbc(key Key, iv [16]byte, encrypt bool, r io.Reader) io.Reader {
	o := make(chan byte)
	e := make(chan error)
	ivBuf := bytes.NewBuffer(iv[:])

	// Create a goroutine which encrypts/decrypts data block by block.
	go func() {
		defer close(e)
		defer close(o)
		var buf [16]byte
		for {
			count, err := r.Read(buf[:])
			if count != 0 {
				if count < 16 {
					e <- fmt.Errorf("padding not supported - supply a multiple of 16 bytes of data")
					return
				}

				if encrypt {
					// XOR-in the next IV block
					var ivBlock [16]byte
					_, err = ivBuf.Read(ivBlock[:])
					if err != nil {
						e <- err
						return
					}
					for i := range buf {
						buf[i] ^= ivBlock[i]
					}
				} else {
					// Append the IV buffer
					ivBuf.Write(buf[:])
				}

				output, err := Rijndael(key, encrypt, buf)
				if err != nil {
					e <- err
					return
				}

				if encrypt {
					// Append the IV buffer
					ivBuf.Write(output[:])
				} else {
					// XOR-in the next IV block
					var ivBlock [16]byte
					_, err = ivBuf.Read(ivBlock[:])
					if err != nil {
						e <- err
						return
					}
					for i := range output {
						output[i] ^= ivBlock[i]
					}
				}
				for _, b := range output {
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
