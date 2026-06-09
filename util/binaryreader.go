package util

import (
	"errors"
	"io"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type BinaryReader struct {
	data []byte
	pos  int
	err  error
}

func (br *BinaryReader) Error() error {
	return br.err
}

// TODO: harden
func (br *BinaryReader) read(l int) []byte {
	if br.err != nil {
		return nil
	}
	if br.pos+l > len(br.data) {
		br.err = errors.New("BinaryReader: EOF: can't read past end of data")
		return nil
	}
	b := br.data[br.pos : br.pos+l]
	br.pos += l
	// println(fmt.Sprintf("read: %X %d/%d", b, br.pos, len(br.data)))
	return b
}
func (br *BinaryReader) ReadBool() bool {
	if br.err != nil {
		return false
	}

	b := br.read(1)[0]
	if b == 1 {
		return true
	} else if b == 0 {
		return false
	}

	br.err = errors.New("ReadBool: invalid bool (not 0 or 1)")
	return false
}
func (br *BinaryReader) ReadU8() uint8 {
	if br.err != nil {
		return 0
	}
	return uint8(br.read(1)[0])
}
func (br *BinaryReader) ReadU16() uint16 {
	if br.err != nil {
		return 0
	}
	return ble.Uint16(br.read(2))
}
func (br *BinaryReader) ReadU24() uint32 {
	if br.err != nil {
		return 0
	}
	b := br.read(3)
	b = append(make([]byte, 0, 4), b...)
	b = append(b, 0)

	return ble.Uint32(b)
}
func (br *BinaryReader) ReadU32() uint32 {
	if br.err != nil {
		return 0
	}
	return ble.Uint32(br.read(4))
}
func (br *BinaryReader) ReadU64() uint64 {
	if br.err != nil {
		return 0
	}
	return ble.Uint64(br.read(8))
}
func (br *BinaryReader) ReadU256() chainhash.Hash {
	h := chainhash.Hash{}
	if br.err != nil {
		return h
	}
	br.err = h.SetBytes(br.read(32))
	return h
}

func (br *BinaryReader) ReadF32() float32 {
	if br.err != nil {
		return 0
	}
	return math.Float32frombits(ble.Uint32(br.read(4)))
}

func (br *BinaryReader) ReadOptionT(dest Array) Array {
	return br.ReadSeq1(dest)
}

func (br *BinaryReader) ReadSeq1(dest Array) Array {
	l := br.ReadU8()
	if l > 1 {
		br.err = errors.New("ReadSeq1: len > 1")
		return nil
	}
	n, err := dest.Decode(int(l), br)
	if err != nil {
		br.err = err
		return nil
	}
	return n
}
func (br *BinaryReader) ReadSeq255(dest Array) Array {
	l := br.ReadU8()
	n, err := dest.Decode(int(l), br)
	if err != nil {
		br.err = err
		return nil
	}
	return n
}
func (br *BinaryReader) ReadSeq64K(dest Array) Array {
	l := br.ReadU16()
	n, err := dest.Decode(int(l), br)
	if err != nil {
		br.err = err
		return nil
	}
	return n
}

func (br *BinaryReader) ReadStr255() string {
	if br.err != nil {
		return ""
	}
	l := int(br.ReadU8())
	return string(br.read(l))
}
func (br *BinaryReader) ReadBin32() []byte {
	if br.err != nil {
		return nil
	}
	l := int(br.ReadU8())
	if l > 32 {
		br.err = errors.New("ReadBin32: len > 32")
		return nil
	}
	b := br.read(l)
	return b
}
func (br *BinaryReader) ReadBin255() []byte {
	if br.err != nil {
		return nil
	}
	l := int(br.ReadU8())
	b := br.read(l)
	return b
}
func (br *BinaryReader) ReadBin64K() []byte {
	if br.err != nil {
		return nil
	}
	l := int(br.ReadU16())
	println(l)
	b := br.read(l)
	return b
}
func (br *BinaryReader) ReadBin16M() []byte {
	if br.err != nil {
		return nil
	}
	l := int(br.ReadU24())
	b := br.read(l)
	return b
}
func (br *BinaryReader) ReadBytes(length int) []byte {
	if br.err != nil {
		return nil
	}
	return br.read(length)
}

func (br *BinaryReader) Read(dest []byte) (int, error) {
	if br.err != nil {
		return 0, br.err
	}
	l := len(dest)
	if l <= 0 {
		return l, io.EOF
	}
	bytesRead := 0
	for i, b := range br.read(l) {
		dest[i] = b
		bytesRead = i
	}
	return bytesRead, br.err
}

func NewBinaryReader(bin []byte) *BinaryReader {
	return &BinaryReader{
		pos:  0,
		data: bin,
	}
}
