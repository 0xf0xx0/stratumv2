package stratumv2

import (
	"errors"
	"io"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

const (
	limit64k = 65535
	limit16m = 2 ^ 24 - 1
)

// inspired by txscript.ScriptBuilder from btcd, and strings.StringBuilder
type BinaryBuilder struct {
	data []byte
	err  error
}

func (bb *BinaryBuilder) Grow(size int) *BinaryBuilder {
	bb.data = make([]byte, 0, size)
	return bb
}
func (bb *BinaryBuilder) Bytes() ([]byte, error) {
	if bb.err != nil {
		return nil, bb.err
	}
	return bb.data, nil
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
func (bb *BinaryBuilder) AddU24(u uint32) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}
	enc := ble.AppendUint32(make([]byte, 0, 4), u)
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
func (bb *BinaryBuilder) AddU256(u chainhash.Hash) *BinaryBuilder {
	if bb.err != nil {
		return bb
	}

	bb.data = append(bb.data, u[:]...)
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

	bb.data = append(bb.data, uint8(l))
	bb.data = append(bb.data, s...)
	return bb
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

	bb.data = append(bb.data, uint8(l))
	bb.data = append(bb.data, s...)
	return bb
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

	bb.data = append(bb.data, uint8(l))
	bb.data = append(bb.data, s...)
	return bb
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

	bb.data = ble.AppendUint16(bb.data, uint16(l))
	bb.data = append(bb.data, s...)
	return bb
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

	bb.AddU24(uint32(l))
	bb.data = append(bb.data, s...)
	return bb
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
	bb.data = append(bb.data, uint8(l))
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	bb.data = append(bb.data, enc...)
	return bb
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
	bb.data = append(bb.data, uint8(l))
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	bb.data = append(bb.data, enc...)
	return bb
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
	bb.AddU16(uint16(l))
	enc, err := things.Encode()
	if err != nil {
		bb.err = err
		return bb
	}
	bb.data = append(bb.data, enc...)
	return bb
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
func (br *BinaryReader) ReadU24() uint32 {
	if br.err != nil {
		return 0
	}
	b := br.read(3)
	if b == nil {
		return 0
	}
	b = append(make([]byte, 0, 4), b...)
	b = append(b, 0)

	return ble.Uint32(b)
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
func (br *BinaryReader) ReadU256() chainhash.Hash {
	h := chainhash.Hash{}
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

func NewBinaryReader(bin []byte) *BinaryReader {
	return &BinaryReader{
		pos:  0,
		data: bin,
	}
}
