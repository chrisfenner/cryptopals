package padding_test

import (
	"bytes"
	"cryptopals/utils/padding"
	"io"
	"testing"
)

func TestPkcs7(t *testing.T) {
	data := []byte{0xff, 0xff, 0xff, 0xff}
	dataBuf := bytes.NewReader(data[:])
	expected1 := []byte{0xff, 0xff, 0xff, 0xff, 3, 3, 3}
	expected2 := []byte{0xff, 0xff, 0xff, 0xff, 4, 4, 4, 4}

	pkcs := padding.Pkcs7(7, dataBuf)
	outBuf := new(bytes.Buffer)

	_, err := io.Copy(outBuf, pkcs)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), expected1[:]) {
		t.Errorf("Want %v got %v", expected1, outBuf.Bytes())
	}

	dataBuf = bytes.NewReader(data[:])
	pkcs = padding.Pkcs7(4, dataBuf)
	outBuf = bytes.NewBuffer(make([]byte, 0))
	_, err = io.Copy(outBuf, pkcs)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), expected2[:]) {
		t.Errorf("Want %v got %v", expected2, outBuf.Bytes())
	}
}

func TestPkcs7MultiReader(t *testing.T) {
	buf1 := bytes.NewReader([]byte{1, 2, 3})
	buf2 := bytes.NewReader([]byte{4, 5, 6, 7, 8})
	expect3 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 1}
	expect4 := []byte{1, 2, 3, 4, 5, 6, 7, 8, 4, 4, 4, 4}

	outBuf := new(bytes.Buffer)
	pkcs := padding.Pkcs7(3, io.MultiReader(buf1, buf2))
	_, err := io.Copy(outBuf, pkcs)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), expect3) {
		t.Errorf("Want %v got %v", expect3, outBuf.Bytes())
	}

	buf1 = bytes.NewReader([]byte{1, 2, 3})
	buf2 = bytes.NewReader([]byte{4, 5, 6, 7, 8})
	pkcs = padding.Pkcs7(4, io.MultiReader(buf1, buf2))
	outBuf = new(bytes.Buffer)
	_, err = io.Copy(outBuf, pkcs)
	if err != nil {
		t.Errorf("Want nil got %v", err)
	}
	if !bytes.Equal(outBuf.Bytes(), expect4) {
		t.Errorf("Want %v got %v", expect4, outBuf.Bytes())
	}
}
