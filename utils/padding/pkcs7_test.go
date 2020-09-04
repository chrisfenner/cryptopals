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
