package util

import (
	"errors"
)

type BinaryReader struct {
	data []byte
	pos  int
	err  error
}

func (br *BinaryReader) Error() error {
	return br.err
}
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
func (br *BinaryReader) ReadBool() (bool, error) {
	if br.err != nil {
		return false, br.err
	}
	b := br.read(1)[0]
	if b == 1 {
		return true, nil
	} else if b == 0 {
		return false, nil
	}
	return false, errors.New("ReadBool: invalid bool (not 0 or 1)")
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
func (br *BinaryReader) ReadStr255() string {
	if br.err != nil {
		return ""
	}
	l := int(br.ReadU8())
	return string(br.read(l))
}
func (br *BinaryReader) ReadBin32() ([]byte, error) {
	if br.err != nil {
		return nil, br.err
	}
	l := int(br.ReadU8())
	if l > 32 {
		return nil, errors.New("ReadBin32: len > 32")
	}
	s := br.read(l)
	return s, nil
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

func NewBinaryReader(bin []byte) *BinaryReader {
	return &BinaryReader{
		pos:  0,
		data: bin,
	}
}
