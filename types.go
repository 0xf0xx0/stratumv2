package stratumv2

// contains all (well, most) of the types used in sv2 and this lib

import (
	"encoding/hex"
	"errors"
)

// helpers
type Protocol uint8
type MessageType uint8
type Error = string
type Flag uint32 // MAYBE: add helpers for setting/clearing bits?
// U24 is the set of all unsigned 24-bit integers.
// Range: 0 through 16777215.
// The top byte gets dropped during encoding.
type U24 uint32

// 3.4
type Extension = uint16

// used for encoding SEQ[T]
//
// to wrap:
//
//	BoolSequence([]bool)
//
// to unwrap:
//
//	dest := []chainhash.Hash(r.ReadSeq255(U256Sequence{}).(U256Sequence))
//
// TODO: is there a better way we can handle these?
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

type U24Sequence []U24

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

type U256Sequence []U256

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

// basically chainhash.Hash with a slightly different set of funcs
//
// you likely want to use chainhash.Hash and cast to U256 when needed
type U256 [32]byte

func (u *U256) SetBytes(b []byte) error {
	l := len(b)
	if l != 32 {
		return errors.New("SetBytes: len not 32")
	}
	copy((*u)[:], b)
	return nil
}
func (u *U256) SetString(s string) error {
	l := len(s)
	if l != 64 {
		return errors.New("SetString: len not 64")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(u[:], b)
	return nil
}

func (u *U256) IsEqual(hash *U256) bool {
	// if theyre the same pointer or nil
	if u == hash {
		return true
	}
	if u == nil || hash == nil {
		return false
	}
	return *u == *hash
}

func (u U256) String() string {
	// flip
	for i := range 16 {
		u[i], u[31-i] = u[31-i], u[i]
	}
	return hex.EncodeToString(u[:])
}

// hash must be less than or equal to the target to be a valid share/block
func (target *U256) IsMetBy(hash *U256) bool {
	for i := range 32 {
		x := 31 - i
		if hash[x] <= target[x] {
			return true
		}
	}
	return false
}
