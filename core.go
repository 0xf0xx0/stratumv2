package stratumv2

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
