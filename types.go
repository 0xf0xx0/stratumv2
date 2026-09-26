package stratumv2

// contains all (well, most) of the types used in sv2 and this lib

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"slices"
)

// helpers
type Protocol uint8
type MessageType uint8
type Error = string
type Flag uint32               // MAYBE: add helpers for setting/clearing bits?
type SuccessFlag uint32        // MAYBE: add helpers for setting/clearing bits?
type Pubkey = [32]byte         // X coordinate of Secp256k1 public key (see BIP 340)
type EllswiftPubkey = [64]byte // ElligatorSwift encoded X coordinate of Secp256k1 [Pubkey] (see BIP 324)
type Signature = [64]byte      // Schnorr signature on Secp256k1 (see BIP 340)

// During the handshake, initiator receives [SIGNATURE_NOISE_MESSAGE] and server's static public key.
// These parts make up a `Certificate` signed by an authority whose public key is generally known (for example from pool's website).
// Initiator confirms the identity of the server by verifying the signature in the certificate.
type Certificate struct {
	Version         uint16 // Version of the certificate format
	ValidFrom       uint32 // Validity start time (unix timestamp)
	NotValidAfter   uint32 // Signature is invalid after this point in time (unix timestamp)
	ServerPubKey    Pubkey
	AuthorityPubKey Pubkey
	Signature       Signature
}

// U24 is the set of all unsigned 24-bit integers.
// Range: 0 through 16777215.
// The top byte gets dropped during encoding.
type U24 uint32

// 3.4
type Extension = uint16

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

func NewFrameFromParams(messageType MessageType, params Codable) (*Frame, error) {
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
		MessageLength: U24(l),
		Payload:       b,
	}, nil
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
	out.Grow(len(a) * 32)
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

// byte-reversed hexadecimal, like [chainhash.Hash.String()].
func (u U256) String() string {
	// flip
	for i := range 16 {
		u[i], u[31-i] = u[31-i], u[i]
	}
	return hex.EncodeToString(u[:])
}

// hash must be less than or equal to the target to be a valid share/block.
func (target *U256) IsMetBy(hash *U256) bool {
	return bytes.Compare(target[:], hash[:]) <= 0
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

// Add adds addend to u and returns u. any carry past 256 bits is discarded.
func (u *U256) Add(addend *U256) *U256 {
	/// TODO: this can be made better right?
	carry := uint16(0)
	for i := range 32 {
		sum := uint16(u[31-i]) + uint16(addend[31-i]) + carry
		carry = (sum & 0xff00) >> 8
		// println(u[31-i], addend[31-i], carry, sum)
		u[31-i] = byte(sum & 0x00ff)
	}
	return u
}

// Sub subtracts subtrahend from u and returns u. overflow is the callers responsibility.
func (u *U256) Sub(subtrahend *U256) *U256 {
	borrow := uint16(0)
	for i := range 32 {
		sample := uint16(u[31-i]) - uint16(subtrahend[31-i])
		if borrow > 0 {
			sample--
		}
		if sample > 255 {
			borrow = 0xff
		} else {
			borrow = 0
		}
		u[31-i] = byte(sample & 0x00ff)
	}
	return u
}

func (t MessageType) String() string {
	ty, _ := MessageTypeToString(t)
	return ty
}

// this will be a BITCH to maintain
// TODO: find better way
func MessageTypeToString(t MessageType) (string, error) {
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
