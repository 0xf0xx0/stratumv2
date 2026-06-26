package stratumv2

import (
	"errors"
	"io"
	"math"
)

const (
	limit64k = 65535
	limit16m = 2 ^ 24 - 1
)

// BinaryBuilder provides helpers for encoding Stratum V2 datatypes.
//
// inspired by txscript.ScriptBuilder from btcd, and strings.StringBuilder
type BinaryBuilder struct {
	data []byte
	err  error
}

// like [strings.Builder.Grow], but doesnt panic when size is negative or zero
func (bb *BinaryBuilder) Grow(size int) *BinaryBuilder {
	if size <= 0 {
		return bb
	}

	l := len(bb.data)
	c := cap(bb.data)
	if c-l < size {
		newData := make([]byte, l, c+size)
		copy(newData, bb.data)
		bb.data = newData
	}
	return bb
}

// like [github.com/btcsuite/btcd/txscript.ScriptBuilder.Script]
//
// Bytes returns the encoded bytes.
// If an error occurred during encoding,
// the encoded bytes will be returned up the point of the first error along with the error.
func (bb *BinaryBuilder) Bytes() ([]byte, error) {
	if bb.err != nil {
		return bb.data, bb.err
	}
	return bb.data, nil
}
func (bb *BinaryBuilder) Len() int {
	return len(bb.data)
}
func (bb *BinaryBuilder) Cap() int {
	return cap(bb.data)
}

func (bb *BinaryBuilder) AddBool(boo bool) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	if boo {
		bb.data = append(bb.data, 1)
		return bb
	}
	bb.data = append(bb.data, 0)
	return bb
}
func (bb *BinaryBuilder) AddU8(u uint8) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.data = append(bb.data, u)
	return bb
}
func (bb *BinaryBuilder) AddU16(u uint16) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}

	bb.data = ble.AppendUint16(bb.data, u)
	return bb
}
func (bb *BinaryBuilder) AddU24(u U24) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	enc := ble.AppendUint32(make([]byte, 0, 4), uint32(u))
	bb.data = append(bb.data, enc[:3]...) // ignore the top byte
	return bb
}
func (bb *BinaryBuilder) AddU32(u uint32) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}

	bb.data = ble.AppendUint32(bb.data, u)
	return bb
}
func (bb *BinaryBuilder) AddU64(u uint64) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}

	bb.data = ble.AppendUint64(bb.data, u)
	return bb
}
func (bb *BinaryBuilder) AddU256(u U256) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.Grow(32)
	bb.AddBytes(u[:])
	return bb
}
func (bb *BinaryBuilder) AddStr255(s string) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := len(s)
	if l > 255 {
		bb.err = errors.New("AddStr: len > 255")
		return bb
	}

	return bb.Grow(l + 1).
		AddU8(uint8(l)).AddBytes([]byte(s))
}
func (bb *BinaryBuilder) AddF32(f float32) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}

	bb.data = ble.AppendUint32(bb.data, math.Float32bits(f))
	return bb
}

func (bb *BinaryBuilder) AddBin32(s []byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := len(s)
	if l > 32 {
		bb.err = errors.New("AddBin32: len > 32")
		return bb
	}

	return bb.Grow(l + 1).
		AddU8(uint8(l)).AddBytes(s)
}
func (bb *BinaryBuilder) AddBin255(s []byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := len(s)
	if l > 255 {
		bb.err = errors.New("AddBin255: len > 255")
		return bb
	}

	return bb.Grow(l + 1).
		AddU8(uint8(l)).AddBytes(s)
}
func (bb *BinaryBuilder) AddBin64K(s []byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := len(s)
	if l > limit64k {
		bb.err = errors.New("AddBin64K: len > 65535")
		return bb
	}

	return bb.Grow(l + 2).
		AddU16(uint16(l)).AddBytes(s)
}
func (bb *BinaryBuilder) AddBin16M(s []byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := len(s)
	if l > limit16m {
		bb.err = errors.New("AddBin16M: len > 2^24-1")
		return bb
	}

	return bb.Grow(l + 3).
		AddU24(U24(l)).
		AddBytes(s)
}

// TODO: use mac
func (bb *BinaryBuilder) AddMAC(mac [16]byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.data = append(bb.data, mac[:]...)
	return bb
}
func (bb *BinaryBuilder) AddPubkey(pubkey [32]byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.data = append(bb.data, pubkey[:]...)
	return bb
}
func (bb *BinaryBuilder) AddSignature(sig [32]byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.data = append(bb.data, sig[:]...)
	return bb
}
func (bb *BinaryBuilder) AddShortTXID(txid [6]byte) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	bb.data = append(bb.data, txid[:]...)
	return bb
}

func (bb *BinaryBuilder) AddOptionT(things Sequence) *BinaryBuilder {
	return bb.AddSeq1(things)
}
func (bb *BinaryBuilder) AddSeq1(things Sequence) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := things.Len()
	if l > 1 {
		bb.err = errors.New("AddSeq1: len > 1")
		return bb
	}
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	return bb.Grow(len(enc) + 1).
		AddU8(uint8(l)).
		AddBytes(enc)
}
func (bb *BinaryBuilder) AddSeq255(things Sequence) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := things.Len()
	if l > 255 {
		bb.err = errors.New("AddSeq255: len > 255")
		return bb
	}
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	return bb.Grow(len(enc) + 1).
		AddU8(uint8(l)).
		AddBytes(enc)
}
func (bb *BinaryBuilder) AddSeq64K(things Sequence) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	l := things.Len()
	if l > 65535 {
		bb.err = errors.New("AddSeq64K: len > 65535")
		return bb
	}
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	return bb.Grow(len(enc) + 2).
		AddU16(uint16(l)).
		AddBytes(enc)
}

func (bb *BinaryBuilder) AddBytes(bin []byte) *BinaryBuilder {
	bb.data = append(bb.data, bin...)
	return bb
}

func NewBinaryBuilder() *BinaryBuilder {
	return &BinaryBuilder{
		data: make([]byte, 0),
	}
}

// BinaryReader wraps a []byte and provides helpers for reading Stratum V2 datatypes.
// It implements [io.Seeker] and [io.Reader].
type BinaryReader struct {
	data []byte
	pos  int
	err  error
}

func (br *BinaryReader) Error() error {
	return br.err
}
func (br *BinaryReader) Remaining() int {
	return len(br.data) - br.pos
}

func (br *BinaryReader) read(l int) []byte {
	if br.err != nil {
		return nil
	}
	if br.pos+l > len(br.data) {
		br.err = errors.New("BinaryReader: EOF: can't read past end of data")
		br.pos = len(br.data)
		return br.data[br.pos:]
	}
	b := br.data[br.pos : br.pos+l]
	br.pos += l
	return b
}
func (br *BinaryReader) ReadBool() bool {
	if br.err != nil {
		return false
	}

	b := br.read(1)
	if b == nil {
		return false
	}
	if b[0] == 1 {
		return true
	} else if b[0] == 0 {
		return false
	}

	br.err = errors.New("ReadBool: invalid bool (not 0 or 1)")
	return false
}
func (br *BinaryReader) ReadU8() uint8 {
	if br.err != nil {
		return 0
	}
	b := br.read(1)
	if b == nil {
		return 0
	}
	return uint8(b[0])
}
func (br *BinaryReader) ReadU16() uint16 {
	if br.err != nil {
		return 0
	}
	b := br.read(2)
	if b == nil {
		return 0
	}
	return ble.Uint16(b)
}
func (br *BinaryReader) ReadU24() U24 {
	if br.err != nil {
		return 0
	}
	b := br.read(3)
	if b == nil {
		return 0
	}
	b = append(make([]byte, 0, 4), b...)
	b = append(b, 0)

	return U24(ble.Uint32(b))
}
func (br *BinaryReader) ReadU32() uint32 {
	if br.err != nil {
		return 0
	}
	b := br.read(4)
	if b == nil {
		return 0
	}
	return ble.Uint32(b)
}
func (br *BinaryReader) ReadU64() uint64 {
	if br.err != nil {
		return 0
	}
	b := br.read(8)
	if b == nil {
		return 0
	}
	return ble.Uint64(b)
}
func (br *BinaryReader) ReadU256() U256 {
	h := U256{}
	if br.err != nil {
		return h
	}
	b := br.read(32)
	if b == nil {
		return h
	}
	br.err = h.SetBytes(b)
	return h
}

func (br *BinaryReader) ReadF32() float32 {
	if br.err != nil {
		return 0
	}
	b := br.read(4)
	if b == nil {
		return 0
	}
	return math.Float32frombits(ble.Uint32(b))
}

func (br *BinaryReader) ReadOptionT(dest Sequence) Sequence {
	return br.ReadSeq1(dest)
}

func (br *BinaryReader) ReadSeq1(dest Sequence) Sequence {
	if br.err != nil {
		return nil
	}
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
func (br *BinaryReader) ReadSeq255(dest Sequence) Sequence {
	if br.err != nil {
		return nil
	}
	l := br.ReadU8()
	n, err := dest.Decode(int(l), br)
	if err != nil {
		br.err = err
		return nil
	}
	return n
}
func (br *BinaryReader) ReadSeq64K(dest Sequence) Sequence {
	if br.err != nil {
		return nil
	}
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
	// println(l)
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

// [io.Reader] impl
func (br *BinaryReader) Read(dest []byte) (int, error) {
	if br.err != nil {
		return 0, br.err
	}
	l := len(dest)
	if l <= 0 {
		return 0, io.EOF
	}
	l = copy(dest, br.read(l))
	return l, br.err
}

// [io.Seeker] impl
func (br *BinaryReader) Seek(offset int64, whence int) (int64, error) {
	if br.err != nil {
		return 0, br.err
	}
	newPos := int(offset)
	switch whence {
	case io.SeekStart:
		newPos = int(offset)
	case io.SeekCurrent:
		newPos += br.pos
	case io.SeekEnd:
		newPos = len(br.data) - int(offset)
	}
	if newPos < 0 || newPos > len(br.data) {
		br.err = errors.New("Seek: out of bounds")
		return 0, br.err
	}
	br.pos = newPos
	return int64(newPos), nil
}

func NewBinaryReader(bin []byte) *BinaryReader {
	return &BinaryReader{
		pos:  0,
		data: bin,
	}
}
