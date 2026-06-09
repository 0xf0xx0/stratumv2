package util

import "github.com/btcsuite/btcd/chaincfg/chainhash"

// used for encoding SEQ[T]
//
// to wrap:
//
//	BoolSequence([]bool)
//
// to unwrap:
//
//	dest := []chainhash.Hash(r.ReadSeq255(util.U256Sequence{}).(util.U256Sequence))
type Sequence interface {
	Encode() ([]byte, error)
	Len() int
	Decode(int, *BinaryReader) (Sequence, error)
}
type BoolSequence []bool

func (a BoolSequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 4)
	for _, v := range a {
		out.AddBool(v)
	}
	return out.Bytes()
}
func (a BoolSequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(BoolSequence, 0, l)
	for range l {
		a = append(a, br.ReadBool())
	}
	return a, br.Error()
}
func (a BoolSequence) Len() int {
	return len(a)
}

type U8Sequence []uint8

func (a U8Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 4)
	for _, v := range a {
		out.AddU8(v)
	}
	return out.Bytes()
}
func (a U8Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U8Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU8())
	}
	return a, br.Error()
}
func (a U8Sequence) Len() int {
	return len(a)
}

type U16Sequence []uint16

func (a U16Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 4)
	for _, v := range a {
		out.AddU16(v)
	}
	return out.Bytes()
}
func (a U16Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U16Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU16())
	}
	return a, br.Error()
}
func (a U16Sequence) Len() int {
	return len(a)
}

type U24Sequence []uint32

func (a U24Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 4)
	for _, v := range a {
		out.AddU24(v)
	}
	return out.Bytes()
}
func (a U24Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U24Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU24())
	}
	return a, br.Error()
}
func (a U24Sequence) Len() int {
	return len(a)
}

type U32Sequence []uint32

func (a U32Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 4)
	for _, v := range a {
		out.AddU32(v)
	}
	return out.Bytes()
}
func (a U32Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U32Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU32())
	}
	return a, br.Error()
}
func (a U32Sequence) Len() int {
	return len(a)
}

type U64Sequence []uint64

func (a U64Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 8)
	for _, v := range a {
		out.AddU64(v)
	}
	return out.Bytes()
}
func (a U64Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U64Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU64())
	}
	return a, br.Error()
}
func (a U64Sequence) Len() int {
	return len(a)
}

type U256Sequence []chainhash.Hash

func (a U256Sequence) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	out.Grow(len(a) * 256)
	for _, v := range a {
		out.AddBytes(v[:])
	}
	return out.Bytes()
}
func (a U256Sequence) Decode(l int, br *BinaryReader) (Sequence, error) {
	a = make(U256Sequence, 0, l)
	for range l {
		a = append(a, br.ReadU256())
	}
	return a, br.Error()
}
func (a U256Sequence) Len() int {
	return len(a)
}
