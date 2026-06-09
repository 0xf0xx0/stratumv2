package util

import (
	"encoding/binary"
	"errors"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

var ble = binary.LittleEndian

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

	/// TODO: validate this
	enc := ble.AppendUint32(make([]byte, 4), u)
	bb.data = append(bb.data, enc[1:]...)
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
