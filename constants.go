package stratumv2

import (
	"encoding/binary"
)

var ble = binary.LittleEndian

const (
	// ProtocolVersion is the latest protocol version this package supports.
	ProtocolVersion   = 2
	ProtocolName      = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256"
	MaxNoiseFrameSize = 65535
	// Serialized stratum-v2 body (payload) is split into 65519-byte chunks and encrypted to form 65535-bytes AEAD ciphertexts
	ChunkSize         = 65519
	MaxPlainFrameSize = MaxNoiseFrameSize - MacLen
	// size of an encrypted header
	NoiseHeaderSize = 22
	// size of a plaintext header
	FrameHeaderSize          = 6
	MacLen                   = 16
	CertificateFormatVersion = 0 // latest supported handshake certificate format version
)

const (
	MessageSetupConnection MessageType = iota
	MessageSetupConnectionSuccess
	MessageSetupConnectionError
	MessageChannelEndpointChanged
	MessageReconnect
)

// Mining Protocol
const (
	MessageOpenStandardMiningChannel MessageType = iota + 0x10
	MessageOpenStandardMiningChannelSuccess
	MessageOpenMiningChannelError
	MessageOpenExtendedMiningChannel
	MessageOpenExtendedMiningChannelSuccess
	MessageNewMiningJob
	MessageUpdateChannel
	MessageUpdateChannelError
	MessageCloseChannel
	MessageSetExtranoncePrefix
	MessageSubmitSharesStandard
	MessageSubmitSharesExtended
	MessageSubmitSharesSuccess
	MessageSubmitSharesError
	MessageReserved
	MessageNewExtendedMiningJob
	MessageSetNewPrevHash
	MessageSetTarget
	MessageSetCustomMiningJob
	MessageSetCustomMiningJobSuccess
	MessageSetCustomMiningJobError
	MessageSetGroupChannel
)

// Job Declaration Protocol
const (
	MessageAllocateMiningJobToken            MessageType = 0x50
	MessageAllocateMiningJobTokenSuccess     MessageType = 0x51
	MessageProvideMissingTransactions        MessageType = 0x55
	MessageProvideMissingTransactionsSuccess MessageType = 0x56
	MessageDeclareMiningJob                  MessageType = 0x57
	MessageDeclareMiningJobSuccess           MessageType = 0x58
	MessageDeclareMiningJobError             MessageType = 0x59
	MessagePushSolution                      MessageType = 0x60
)

const (
	UnsupportedFeatureFlagsError Error = "unsupported-feature-flags"
	UnsupportedProtocolError     Error = "unsupported-protocol"
	ProtocolVersionMismatchError Error = "protocol-version-mismatch"

	// mining errors

	UnknownUserError           Error = "unknown-user"
	MaxTargetOutOfRangeError   Error = "max-target-out-of-range"
	InvalidChannelIDError      Error = "invalid-channel-id"
	StaleShareError            Error = "stale-share"
	DifficultyTooLowError      Error = "difficulty-too-low"
	InvalidJobIDError          Error = "invalid-job-id"
	InvalidMiningJobTokenError Error = "invalid-mining-job-token"
)

const (
	ExtensionTypeMinValid Extension = 0x4000
	ExtensionTypeMaxValid Extension = 0x7fff
	ExtensionTypeCore     Extension = 0
	// TODO: list valid extensions
	ExtensionNegotiaton                     Extension = 0x0001
	ExtensionWorkerSpecificHashrateTracking Extension = 0x0002
)
