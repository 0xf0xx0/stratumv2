package stratumv2

import (
	"errors"
	"io"
)

const (
	MiningProtocol Protocol = iota
	JobDeclarationProtocol
	TemplateDistributionProtocol
)

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
	MessageType Method
	// Length of the protocol message, not including this header
	MessageLength U24
	// Message-specific payload of length MessageLength.
	// If the MSB in ExtensionType (the `channel_msg` bit) is set the first
	// four bytes are defined as a U32 "channel_id", though this definition is
	// repeated in the message definitions below and these 4 bytes are included in MessageLength.
	Payload []byte // MAYBE: make Message interface? would that fuck up the current handling?
	TLVs    []TLV  // appended to Payload on .Encode()
}

func (f *Frame) Encode() ([]byte, error) {
	if int(f.MessageLength) != len(f.Payload) {
		return nil, errors.New("Frame.Encode: MessageLength != len(Payload)")
	}
	out := NewBinaryBuilder().Grow(int(f.MessageLength))
	out.AddU16(f.ExtensionType).
		AddU8(uint8(f.MessageType)).
		AddU24(f.MessageLength).
		AddBytes(f.Payload)
	if f.TLVs != nil {
		for _, tlv := range f.TLVs {
			enc, err := tlv.Encode()
			if err != nil {
				return nil, err
			}
			out.AddBytes(enc)
		}
		f.MessageLength = U24(out.Len())
	}

	return out.Bytes()
}

// Decode decodes the full frame from the given byte slice.
func (f *Frame) Decode(b []byte) error {
	r := NewBinaryReader(b)
	f.ExtensionType = r.ReadU16()
	messageType := r.ReadU8()
	f.MessageType = Method(messageType)
	f.MessageLength = r.ReadU24()
	f.Payload = r.ReadBytes(int(f.MessageLength))
	return r.Error()
}

// DecodeHeader decodes just the frame header from the given byte slice.
func (f *Frame) DecodeHeader(b []byte) error {
	r := NewBinaryReader(b)
	f.ExtensionType = r.ReadU16()
	messageType := r.ReadU8()
	f.MessageType = Method(messageType)
	f.MessageLength = r.ReadU24()
	return r.Error()
}
func (f *Frame) DecodeFromReader(r io.Reader) error {
	var err error

	header := make([]byte, 6)
	if _, err = r.Read(header); err != nil {
		return err
	}

	if err = f.DecodeHeader(header); err != nil {
		return err
	}
	f.Payload = make([]byte, f.MessageLength)
	if _, err = r.Read(f.Payload); err != nil {
		return err
	}
	return nil
}

type TLV struct {
	// Identifies the TLV field.
	// The first 2 bytes represent the extension_type, and the third byte represents the field_type within the extension context.
	Type   U24
	Length uint16 // Indicates the size (in bytes) of the Value field.
	Value  []byte // The actual data of the extension field, of variable length.
}

func (t *TLV) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(len(t.Value) + 32).
		AddU24(t.Type).
		AddU16(t.Length).
		AddBin64K(t.Value).Bytes()
}
func (t *TLV) Decode(b []byte) error {
	r := NewBinaryReader(b)
	t.Type = r.ReadU24()
	t.Length = r.ReadU16()
	t.Value = r.ReadBytes(int(t.Length))
	return r.Error()
}

// SetupConnection MUST be the first message sent by the client on the newly opened connection.
// Server MUST respond with either a [SetupConnectionSuccess] or [SetupConnectionError] message.
// Clients that are not configured to provide telemetry data to the upstream node SHOULD set
// [SetupConnection.DeviceID] to 0-length strings.
// However, they MUST always set vendor to a string describing the manufacturer/developer and
// firmware version and SHOULD always set [SetupConnection.DeviceHardwareVersion] to a string describing, at least,
// the particular hardware/software package in use.
type SetupConnection struct {
	Protocol   Protocol // 0 = Mining Protocol 1 = Job Declaration 2 = Template Distribution Protocol
	MinVersion uint16   // The minimum protocol version the client supports (currently must be 2)
	MaxVersion uint16   // The maximum protocol version the client supports (currently must be 2)
	// Flags indicating optional protocol features the client supports.
	// Each protocol from protocol field as its own values/flags.
	Flags                 Flag
	EndpointPort          uint16 // Connecting port value
	EndpointHost          string // ASCII text indicating the hostname or IP address, truncated at 255 chars
	DeviceVendor          string // E.g. "Bitaxe"
	DeviceHardwareVersion string // E.g. "BM1370"
	DeviceFirmware        string // E.g. "esp-miner v2.14.0"
	DeviceID              string // Unique identifier of the device as defined by the vendor
}

func (m *SetupConnection) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(256)
	out.AddU8(uint8(m.Protocol)).
		AddU16(m.MinVersion).
		AddU16(m.MaxVersion).
		AddU32(uint32(m.Flags)).
		AddStr255(m.EndpointHost).
		AddU16(m.EndpointPort).
		AddStr255(m.DeviceVendor).
		AddStr255(m.DeviceHardwareVersion).
		AddStr255(m.DeviceFirmware).
		AddStr255(m.DeviceID)

	return out.Bytes()
}
func (m *SetupConnection) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.Protocol = Protocol(r.ReadU8())
	m.MinVersion = r.ReadU16()
	m.MaxVersion = r.ReadU16()
	m.Flags = Flag(r.ReadU32())
	m.EndpointHost = r.ReadStr255()
	m.EndpointPort = r.ReadU16()
	m.DeviceVendor = r.ReadStr255()
	m.DeviceHardwareVersion = r.ReadStr255()
	m.DeviceFirmware = r.ReadStr255()
	m.DeviceID = r.ReadStr255()
	return r.Error()
}

type SetupConnectionSuccess struct {
	UsedVersion uint16 // Selected version proposed by the connecting node that the upstream node supports. This version will be used on the connection for the rest of its life.
	Flags       Flag   // Flags indicating optional protocol features the server supports. Each protocol from protocol field has its own values/flags.
}

func (m *SetupConnectionSuccess) Encode() ([]byte, error) {
	return NewBinaryBuilder().
		Grow(6).
		AddU16(m.UsedVersion).
		AddU32(uint32(m.Flags)).
		Bytes()
}
func (m *SetupConnectionSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.UsedVersion = r.ReadU16()
	m.Flags = Flag(r.ReadU32())
	return r.Error()
}

// Possible errors: [UnsupportedFeatureFlagsError], [UnsupportedProtocolError], [ProtocolVersionMismatchError]
type SetupConnectionError struct {
	Flags     Flag  // Flags indicating features causing an error
	ErrorCode Error // Person-readable error code(s)
}

func (m *SetupConnectionError) Encode() ([]byte, error) {
	return NewBinaryBuilder().
		Grow(259).
		AddU32(uint32(m.Flags)).
		AddStr255(string(m.ErrorCode)).
		Bytes()
}
func (m *SetupConnectionError) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.Flags = Flag(r.ReadU32())
	m.ErrorCode = Error(r.ReadStr255())
	return r.Error()
}

// When a channel’s upstream or downstream endpoint changes and that channel had previously
// sent messages with channel_msg bitset of unknown extension_type, the intermediate proxy
// MUST send a [ChannelEndpointChanged] message. Upon receipt thereof, any extension state
// (including version negotiation and the presence of support for a given extension)
// MUST be reset and version/presence negotiation must begin again.
type ChannelEndpointChanged struct {
	ChannelID uint32 // The channel which has changed endpoint
}

func (m *ChannelEndpointChanged) Encode() ([]byte, error) {
	return NewBinaryBuilder().AddU32(m.ChannelID).Bytes()
}
func (m *ChannelEndpointChanged) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.ChannelID = r.ReadU32()
	return r.Error()
}

// Reconnect allows clients to be redirected to a new upstream node.
// This message is connection-related so that it should not be propagated downstream
// by intermediate proxies.
// Upon receiving the message, the client re-initiates the Noise handshake and uses the
// pool’s authority public key to verify that the certificate presented by the new server
// has a valid signature.
//
// For security reasons, it is not possible to reconnect to a server with a certificate signed
// by a different pool authority key.
// The message intentionally does not contain a pool public key and thus cannot be used to
// reconnect to a different pool.
// This ensures that an attacker will not be able to redirect hashrate to an arbitrary server
// should the pool server get compromised and instructed to send reconnects to a new location.
type Reconnect struct {
	NewHost string // When empty, downstream node attempts to reconnect to its present host
	NewPort uint16 // When 0, downstream node attempts to reconnect to its present port
}

func (m *Reconnect) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(257).AddStr255(m.NewHost).AddU16(m.NewPort).Bytes()
}
func (m *Reconnect) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.NewHost = r.ReadStr255()
	m.NewPort = r.ReadU16()
	return r.Error()
}
