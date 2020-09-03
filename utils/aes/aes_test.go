package aes_test

import (
	"bytes"
	"cryptopals/utils/aes"
	"io"
	"testing"
)

func TestSubBytes(t *testing.T) {
	var data [16]byte
	aes.SubBytes(&data, true)
	for i := 0; i < 16; i++ {
		if data[i] != 0x63 {
			t.Errorf("Want all 0x63 bytes")
		}
	}
	aes.SubBytes(&data, false)
	for i := 0; i < 16; i++ {
		if data[i] != 0x00 {
			t.Errorf("Want all 0x00 bytes")
		}
	}
}

func TestMixColumns(t *testing.T) {
	data := [16]byte{0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6, 0xd4, 0xd4, 0xd4, 0xd5, 0x2d, 0x26, 0x31, 0x4c}
	expected1 := [16]byte{0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6, 0xd5, 0xd5, 0xd7, 0xd6, 0x4d, 0x7e, 0xbd, 0xf8}
	expected2 := [16]byte{0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6, 0xc6, 0xc6, 0xd4, 0xd4, 0xd4, 0xd5, 0x2d, 0x26, 0x31, 0x4c}
	aes.MixColumns(&data, true)
	if !bytes.Equal(data[:], expected1[:]) {
		t.Errorf("Want %v got %v", expected1, data)
	}
	aes.MixColumns(&data, false)
	if !bytes.Equal(data[:], expected2[:]) {
		t.Errorf("Want %v got %v", expected2, data)
	}
}

func TestShiftRows(t *testing.T) {
	data := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	expected1 := [16]byte{0x00, 0x05, 0x0a, 0x0f, 0x04, 0x09, 0x0e, 0x03, 0x08, 0x0d, 0x02, 0x07, 0x0c, 0x01, 0x06, 0x0b}
	expected2 := [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	aes.ShiftRows(&data, true)
	if !bytes.Equal(data[:], expected1[:]) {
		t.Errorf("Want %v got %v", expected1, data)
	}
	aes.ShiftRows(&data, false)
	if !bytes.Equal(data[:], expected2[:]) {
		t.Errorf("Want %v got %v", expected2, data)
	}
}

func TestKeySchedule(t *testing.T) {
	key := aes.NewKey128([16]byte{0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75})

	expected := [][16]byte{
		[16]byte{0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20, 0x46, 0x75},
		[16]byte{0xE2, 0x32, 0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88, 0xB1, 0x59, 0xE4, 0xE6, 0xD6, 0x79, 0xA2, 0x93},
		[16]byte{0x56, 0x08, 0x20, 0x07, 0xC7, 0x1A, 0xB1, 0x8F, 0x76, 0x43, 0x55, 0x69, 0xA0, 0x3A, 0xF7, 0xFA},
		[16]byte{0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A, 0xBC, 0x68, 0x63, 0x39, 0xE9, 0x01, 0xC3, 0x03, 0x1E, 0xFB},
		[16]byte{0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1, 0xD7, 0x51, 0x57, 0xA0, 0x14, 0x52, 0x49, 0x5B},
		[16]byte{0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92, 0xD2, 0x10, 0xD2, 0x32, 0xC6, 0x42, 0x9B, 0x69},
		[16]byte{0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15, 0x6A, 0x6C, 0x95, 0x27, 0xAC, 0x2E, 0x0E, 0x4E},
		[16]byte{0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03, 0x1E, 0x86, 0x3F, 0x24, 0xB2, 0xA8, 0x31, 0x6A},
		[16]byte{0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22, 0xE4, 0x3D, 0x7A, 0x06, 0x56, 0x95, 0x4B, 0x6C},
		[16]byte{0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2, 0xA1, 0x64, 0x80, 0xB4, 0xF7, 0xF1, 0xCB, 0xD8},
		[16]byte{0x28, 0xFD, 0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A, 0xCC, 0xC0, 0xA4, 0xFE, 0x3B, 0x31, 0x6F, 0x26},
	}

	rounds := key.KeySchedule()
	for i := 0; i < len(expected); i++ {
		roundKey, ok := <-rounds
		if !ok {
			t.Errorf("Key schedule missing round %d", i)
		}
		if !bytes.Equal(roundKey[:], expected[i][:]) {
			t.Errorf("For round %d want %v got %v", i, expected[i], roundKey)
		}
	}
	_, ok := <-rounds
	if ok {
		t.Errorf("Key schedule too long")
	}
}

func TestRijndael(t *testing.T) {
	key := aes.NewKey128([16]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	data := [16]byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}
	expected := [16]byte{0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97}

	result, err := aes.Rijndael(key, true, data)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(result[:], expected[:]) {
		t.Errorf("Want %v got %v", expected, result)
	}
}

func TestEcb(t *testing.T) {
	key := aes.NewKey128([16]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	data := [16]byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}
	expected := [16]byte{0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97}

	dataBuf := bytes.NewBuffer(data[:])
	encryptor := aes.Ecb(key, true, dataBuf)

	encrypted := bytes.NewBuffer([]byte{})
	_, err := io.Copy(encrypted, encryptor)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(expected[:], encrypted.Bytes()) {
		t.Errorf("Want %v got %v", expected, encrypted.Bytes())
	}

	// Now do it in reverse
	data = [16]byte{0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97}
	expected = [16]byte{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}

	dataBuf = bytes.NewBuffer(data[:])
	encryptor = aes.Ecb(key, false, dataBuf)

	encrypted = bytes.NewBuffer([]byte{})
	_, err = io.Copy(encrypted, encryptor)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(expected[:], encrypted.Bytes()) {
		t.Errorf("Want %v got %v", expected, encrypted.Bytes())
	}
}

func TestCbc(t *testing.T) {
	key := aes.NewKey128([16]byte{0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a})
	iv := [16]byte{0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58}
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	expected := []byte{0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
		0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1}

	dataBuf := bytes.NewBuffer(data[:])
	encryptor := aes.Cbc(key, iv, true, dataBuf)

	encrypted := bytes.NewBuffer([]byte{})
	_, err := io.Copy(encrypted, encryptor)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(expected[:], encrypted.Bytes()) {
		t.Errorf("Want %v got %v", expected, encrypted.Bytes())
	}

	// Now do it in reverse
	data = []byte{0xd2, 0x96, 0xcd, 0x94, 0xc2, 0xcc, 0xcf, 0x8a, 0x3a, 0x86, 0x30, 0x28, 0xb5, 0xe1, 0xdc, 0x0a,
		0x75, 0x86, 0x60, 0x2d, 0x25, 0x3c, 0xff, 0xf9, 0x1b, 0x82, 0x66, 0xbe, 0xa6, 0xd6, 0x1a, 0xb1}
	expected = []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}

	dataBuf = bytes.NewBuffer(data[:])
	encryptor = aes.Cbc(key, iv, false, dataBuf)

	encrypted = bytes.NewBuffer([]byte{})
	_, err = io.Copy(encrypted, encryptor)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(expected[:], encrypted.Bytes()) {
		t.Errorf("Want %v got %v", expected, encrypted.Bytes())
	}
}
