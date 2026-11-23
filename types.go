package stratumv2

// contains all (well, most) of the types used in sv2 and this lib

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"slices"

	"github.com/btcsuite/btcd/chainhash/v2"
)

// helpers
type Protocol uint8
type MessageType uint8
type Error = string
type Flag uint32               // [MessageSetupConnection] and [MessageSetupConnectionError] flags
type SuccessFlag uint32        // [MessageSetupConnectionSuccess] flags
type Pubkey = [32]byte         // X coordinate of Secp256k1 public key (see BIP 340)
type EllswiftPubkey = [64]byte // ElligatorSwift encoded X coordinate of Secp256k1 [Pubkey] (see BIP 324)
type Signature = [64]byte      // Schnorr signature on Secp256k1 (see BIP 340)

type STR0_255 = string
type B0_32 = []byte // Byte array with 8-bit length prefix L. Unsigned integer, followed by a sequence of L bytes. Allowed range of length is 0 to 32.
type B0_255 = []byte
type B0_64K = []byte
type B0_16M = []byte

// U24 is the set of all unsigned 24-bit integers.
// Range: 0 through 16777215.
// The top byte gets dropped during encoding.
type U24 uint32

// 3.4
type Extension = uint16

// Codable is the base interface for encoding and decoding sv2 chatter.
// [Frame] and all messages implement this interface.
// TODO: io.reader interface
type Codable interface {
	Encode() ([]byte, error)
	Decode([]byte) error
	// MAYBE: String() string for pretty-printing?
}

// a Frame packages a payload for sending over the wire.
type Frame struct {
	// Unique identifier of the extension associated with this protocol message.
	// For messages defined in the core specification
	// (Common, Mining, Job Declaration, and Template Distribution Protocols,
	// which can only be extended via [TLV] fields), this field MUST be set to [ExtensionTypeCore].
	// For messages introduced by an extension, this field MUST be set to that extension's identifier.
	// Note that even if a message is later modified by a different extension through
	// [TLV] fields, the ExtensionType of the base frame remains set to the extension
	// that originally defined the message structure.
	ExtensionType Extension
	// Unique identifier of this protocol message
	MessageType MessageType
	// Length of the protocol message, not including this header
	MessageLength U24
	// Message-specific payload of length MessageLength.
	// If the MSB in ExtensionType (the `channel_msg` bit) is set the first
	// four bytes are defined as a U32 "channel_id", though this definition is
	// repeated in the message definitions below and these 4 bytes are included in MessageLength.
	Payload []byte // MAYBE: make Message interface? would that fuck up the current handling?
	TLVs    []TLV  // appended to Payload on .Encode()
}

func NewFrameFromParams(messageType MessageType, extensionType Extension, params Codable) (*Frame, error) {
	b, err := params.Encode()
	if err != nil {
		return nil, err
	}
	l := len(b)
	if l > MaxU24 {
		return nil, errors.New("Frame.Encode: MessageLength > MaxU24")
	}
	return &Frame{
		MessageType:   messageType,
		ExtensionType: extensionType,
		MessageLength: U24(l),
		Payload:       b,
	}, nil
}

// FromParams is a wrapper around [NewFrameFromParams].
func (f *Frame) FromParams(messageType MessageType, params Codable) error {
	frame, err := NewFrameFromParams(messageType, ExtensionTypeCore, params)
	if err != nil {
		return err
	}
	*f = *frame
	return nil
}

// FromParams is a wrapper around [NewFrameFromParams].
func (f *Frame) FromParamsExtension(messageType MessageType, extensionType Extension, params Codable) error {
	frame, err := NewFrameFromParams(messageType, extensionType, params)
	if err != nil {
		return err
	}
	*f = *frame
	return nil
}

// ToParams decodes the frame parameters to `params`.
func (f *Frame) ToParams(params Codable) error {
	return params.Decode(f.Payload)
}

func (f *Frame) Encode() ([]byte, error) {
	if int(f.MessageLength) != len(f.Payload) {
		return nil, errors.New("Frame.Encode: MessageLength != len(Payload)")
	}
	out := NewBinaryBuilder().Grow(FrameHeaderSize + int(f.MessageLength))
	/// FIXME: properly encode tlvs
	if f.TLVs != nil {
		tlvOut := NewBinaryBuilder()
		/// "TLV fields MUST be ordered by extension_type.
		///  Since all extensions are negotiated beforehand,
		///  the recipient MUST process TLV fields in order of
		//   extension_type and use their Type identifiers to correctly interpret them.
		slices.SortStableFunc(f.TLVs, func(i, j TLV) int {
			if i.ExtensionType > j.ExtensionType {
				return 1
			}
			if i.ExtensionType < j.ExtensionType {
				return -1
			}
			return 0
		})
		for _, tlv := range f.TLVs {
			enc, err := tlv.Encode()
			if err != nil {
				return nil, err
			}
			tlvOut.AddBytes(enc)
		}
		f.MessageLength += U24(tlvOut.Len())
		b, err := tlvOut.Bytes()
		if err != nil {
			return nil, err
		}
		f.Payload = append(f.Payload, b...)
	}
	out.AddU16(f.ExtensionType).
		AddU8(uint8(f.MessageType)).
		AddU24(f.MessageLength).
		AddBytes(f.Payload)

	return out.Bytes()
}

// Decode decodes the full frame from the given byte slice.
func (f *Frame) Decode(b []byte) error {
	err := f.DecodeHeader(b[:FrameHeaderSize])
	if err != nil {
		return err
	}
	n := FrameHeaderSize + int(f.MessageLength)
	err = f.ReadPayload(b[FrameHeaderSize:n])
	if err != nil {
		return err
	}
	// U24+U16 = 5 bytes
	// if remainder is less than this its just garbage
	l := len(b)
	if l > n+5 {
		lastLen := 0
		for {
			if l-(n+lastLen) < 5 {
				return nil
			}
			tlv := TLV{}
			err := tlv.Decode(b[n+lastLen:])
			if err != nil {
				return err
			}
			f.TLVs = append(f.TLVs, tlv)
			lastLen += int(tlv.Length) + 5
		}
	}
	return err
}

// DecodeHeader decodes just the frame header from the given byte slice.
func (f *Frame) DecodeHeader(b []byte) error {
	r := NewBinaryReader(b)
	f.ExtensionType = r.ReadU16()
	f.MessageType = MessageType(r.ReadU8())
	f.MessageLength = r.ReadU24()
	return r.Error()
}

// ReadPayload reads the payload from the given byte slice. It should be called after DecodeHeader.
func (f *Frame) ReadPayload(b []byte) error {
	r := NewBinaryReader(b)
	f.Payload = r.ReadBytes(int(f.MessageLength))
	return r.Error()
}
func (f *Frame) DecodeFromReader(r io.Reader) error {
	var err error

	header := make([]byte, FrameHeaderSize)
	if _, err = io.ReadFull(r, header); err != nil {
		return err
	}

	if err = f.DecodeHeader(header); err != nil {
		return err
	}

	f.Payload = make([]byte, f.MessageLength)
	if _, err = io.ReadFull(r, f.Payload); err != nil {
		return err
	}
	return nil
}

type TLV struct {
	// Identifies the TLV field.
	// The first 2 bytes represent the extension_type,
	ExtensionType uint16
	// and the third byte represents the field_type within the extension context.
	FieldType uint8
	Length    uint16 // Indicates the size (in bytes) of the Value field.
	Value     []byte // The actual data of the extension field, of variable length.
}

func (t *TLV) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(len(t.Value) + 5).
		AddU16(t.ExtensionType).
		AddU8(t.FieldType).
		AddU16(t.Length).
		AddBin64K(t.Value).Bytes()
}
func (t *TLV) Decode(b []byte) error {
	r := NewBinaryReader(b)
	t.ExtensionType = r.ReadU16()
	t.FieldType = r.ReadU8()
	t.Length = r.ReadU16()
	t.Value = r.ReadBytes(int(t.Length))
	return r.Error()
}

// basically chainhash.Hash with a slightly different set of funcs
//
// you likely want to use chainhash.Hash and cast to U256 when needed
type U256 [32]byte

func (u *U256) Clone() *U256 {
	clone := &U256{}
	clone.SetBytes(u[:])
	return clone
}

// CloneBytes returns a copy of the U256 as a byte slice.
func (u *U256) CloneBytes() []byte {
	makeCopy := make([]byte, 32)
	copy(makeCopy, u[:])
	return makeCopy
}

// SetBytes sets the U256 from a byte slice of length 32.
func (u *U256) SetBytes(b []byte) error {
	if len(b) != 32 {
		return errors.New("SetBytes: len not 32")
	}
	copy((*u)[:], b)
	return nil
}

// SetString sets the U256 from a hex string of length 64.
func (u *U256) SetString(s string) error {
	if len(s) != 64 {
		return errors.New("SetString: len not 64")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	copy(u[:], b)
	return nil
}

// String returns a byte-reversed hex string, like [chainhash.Hash.String].
func (u U256) String() string {
	// flip
	for i := range 16 {
		u[i], u[31-i] = u[31-i], u[i]
	}
	return hex.EncodeToString(u[:])
}

// StringNonReversed is like [U256.String] but without the reversing.
func (u U256) StringNonReversed() string {
	return hex.EncodeToString(u[:])
}

// hash must be less than or equal to the target to be a valid share/block.
func (target *U256) IsMetBy(u256 *U256) bool {
	return target.Compare(u256) >= 0
}

// see [U256.IsMetBy].
func (target *U256) IsMetByHash(hash *chainhash.Hash) bool {
	hashU256 := U256(*hash)
	return target.Compare(&hashU256) >= 0
}

// Compare returns an integer comparing a U256 to a target U256.
// it returns 0 if hash == target, 1 if hash < target, and -1 if hash > target.
// a nil argument is equivalent to an empty slice.
func (target *U256) Compare(hash *U256) int {
	if hash == nil {
		hash = &U256{}
	}
	/// big-endian byte order, so plain byte comparison is numeric comparison
	return bytes.Compare(target[:], hash[:])
}
func (u *U256) IsEqual(hash U256) bool {
	return bytes.Equal(u[:], hash[:])
}

// toLimbs returns u as four 64-bit limbs in little-endian order
// (limbs[0] is the least significant limb).
func (u *U256) toLimbs() (limbs [4]uint64) {
	for i := range 4 {
		limbs[i] = binary.BigEndian.Uint64(u[24-8*i : 32-8*i])
	}
	return limbs
}

// fromLimbs sets u from four 64-bit limbs in little-endian order.
func (u *U256) fromLimbs(limbs [4]uint64) {
	for i := range 4 {
		binary.BigEndian.PutUint64(u[24-8*i:32-8*i], limbs[i])
	}
}

// Add adds addend to u and returns u. any carry past 256 bits is discarded.
func (u *U256) Add(addend U256) *U256 {
	x := u.toLimbs()
	y := addend.toLimbs()
	var carry uint64
	for i := range 4 {
		x[i], carry = bits.Add64(x[i], y[i], carry)
	}
	u.fromLimbs(x)
	return u
}

// Sub subtracts subtrahend from u and returns u, wrapping around 2^256 on underflow.
func (u *U256) Sub(subtrahend U256) *U256 {
	x := u.toLimbs()
	y := subtrahend.toLimbs()
	var borrow uint64
	for i := range 4 {
		x[i], borrow = bits.Sub64(x[i], y[i], borrow)
	}
	u.fromLimbs(x)
	return u
}

// Mul multiplies u by multiplicand and returns u.
// The result is taken modulo 2^256: any bits past 256 are discarded.
func (u *U256) Mul(multiplicand U256) *U256 {
	a := u.toLimbs()
	b := multiplicand.toLimbs()
	var r [4]uint64
	for i := range 4 {
		var carry uint64
		for j := 0; j+i < 4; j++ {
			hi, lo := bits.Mul64(a[i], b[j])
			/// accumulate r[i+j] and the running carry into the 128-bit product hi:lo.
			/// this cannot overflow, since a*b + (2^64-1) + (2^64-1) < 2^128.
			var c uint64
			lo, c = bits.Add64(lo, r[i+j], 0)
			hi, _ = bits.Add64(hi, 0, c)
			lo, c = bits.Add64(lo, carry, 0)
			hi, _ = bits.Add64(hi, 0, c)
			r[i+j] = lo
			carry = hi
		}
		/// any remaining carry lands past 256 bits and is discarded
	}
	u.fromLimbs(r)
	return u
}

// Div divides u by divisor and returns u holding the quotient (truncated division).
// It panics if divisor is zero.
func (u *U256) Div(divisor U256) *U256 {
	d := divisor.toLimbs()
	if d == ([4]uint64{}) {
		panic("U256.Div: division by zero")
	}
	n := u.toLimbs()
	var q, r [4]uint64
	/// binary long division, one bit at a time from the top
	for i := 255; i >= 0; i-- {
		/// r = (r << 1) | bit i of n
		r[3] = r[3]<<1 | r[2]>>63
		r[2] = r[2]<<1 | r[1]>>63
		r[1] = r[1]<<1 | r[0]>>63
		r[0] = r[0]<<1 | (n[i/64]>>(i%64))&1
		if cmpLimbs(r, d) >= 0 {
			var borrow uint64
			for j := range 4 {
				r[j], borrow = bits.Sub64(r[j], d[j], borrow)
			}
			q[i/64] |= 1 << (i % 64)
		}
	}
	u.fromLimbs(q)
	return u
}

// cmpLimbs compares a and b, returning -1, 0, or 1.
func cmpLimbs(a, b [4]uint64) int {
	for i := 3; i >= 0; i-- {
		if a[i] > b[i] {
			return 1
		}
		if a[i] < b[i] {
			return -1
		}
	}
	return 0
}

func (t MessageType) String() string {
	ty, _ := messageTypeToString(t)
	return ty
}

// this will be a BITCH to maintain
// TODO: find better way
func messageTypeToString(t MessageType) (string, error) {
	switch t {
	case MessageAllocateMiningJobToken:
		return "AllocateMiningJobToken", nil
	case MessageAllocateMiningJobTokenSuccess:
		return "AllocateMiningJobTokenSuccess", nil
	case MessageChannelEndpointChanged:
		return "ChannelEndpointChanged", nil
	case MessageCloseChannel:
		return "CloseChannel", nil
	case MessageDeclareMiningJob:
		return "DeclareMiningJob", nil
	case MessageDeclareMiningJobError:
		return "DeclareMiningJobError", nil
	case MessageDeclareMiningJobSuccess:
		return "DeclareMiningJobSuccess", nil
	case MessageNewExtendedMiningJob:
		return "NewExtendedMiningJob", nil
	case MessageNewMiningJob:
		return "NewMiningJob", nil
	case MessageOpenExtendedMiningChannel:
		return "OpenExtendedMiningChannel", nil
	case MessageOpenExtendedMiningChannelSuccess:
		return "OpenExtendedMiningChannelSuccess", nil
	case MessageOpenMiningChannelError:
		return "OpenMiningChannelError", nil
	case MessageOpenStandardMiningChannel:
		return "OpenStandardMiningChannel", nil
	case MessageOpenStandardMiningChannelSuccess:
		return "OpenStandardMiningChannelSuccess", nil
	case MessageProvideMissingTransactions:
		return "ProvideMissingTransactions", nil
	case MessageProvideMissingTransactionsSuccess:
		return "ProvideMissingTransactionsSuccess", nil
	case MessagePushSolution:
		return "PushSolution", nil
	case MessageReconnect:
		return "Reconnect", nil
	case MessageReserved:
		return "Reserved", nil
	case MessageSetCustomMiningJob:
		return "SetCustomMiningJob", nil
	case MessageSetCustomMiningJobError:
		return "SetCustomMiningJobError", nil
	case MessageSetCustomMiningJobSuccess:
		return "SetCustomMiningJobSuccess", nil
	case MessageSetExtranoncePrefix:
		return "SetExtranoncePrefix", nil
	case MessageSetGroupChannel:
		return "SetGroupChannel", nil
	case MessageSetNewPrevHash:
		return "SetNewPrevHash", nil
	case MessageSetTarget:
		return "SetTarget", nil
	case MessageSetupConnection:
		return "SetupConnection", nil
	case MessageSetupConnectionError:
		return "SetupConnectionError", nil
	case MessageSetupConnectionSuccess:
		return "SetupConnectionSuccess", nil
	case MessageSubmitSharesError:
		return "SubmitSharesError", nil
	case MessageSubmitSharesExtended:
		return "SubmitSharesExtended", nil
	case MessageSubmitSharesStandard:
		return "SubmitSharesStandard", nil
	case MessageSubmitSharesSuccess:
		return "SubmitSharesSuccess", nil
	case MessageUpdateChannel:
		return "UpdateChannel", nil
	case MessageUpdateChannelError:
		return "UpdateChannelError", nil
	}
	return "", errors.New("unknown message type")
}
