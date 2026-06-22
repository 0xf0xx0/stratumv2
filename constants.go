package stratumv2

import (
	"encoding/binary"
)

var ble = binary.LittleEndian

const (
	// ProtocolVersion is the latest protocol version this package supports.
	ProtocolVersion   = 2
	MaxNoiseFrameSize = 2<<16 - 1
	// Serialized stratum-v2 body (payload) is split into 65519-byte chunks and encrypted to form 65535-bytes AEAD ciphertexts
	ChunkSize         = 65519
	MaxPlainFrameSize = MaxNoiseFrameSize - MacLen
	NoiseHeaderSize   = 22
	FrameHeaderSize   = 6
	MacLen            = 16
)

const (
	MethodSetupConnection Method = iota
	MethodSetupConnectionSuccess
	MethodSetupConnectionError
	MethodChannelEndpointChanged
	MethodReconnect
)

// Mining Protocol
const (
	MethodOpenStandardMiningChannel Method = iota + 0x10
	MethodOpenStandardMiningChannelSuccess
	MethodOpenMiningChannelError
	MethodOpenExtendedMiningChannel
	MethodOpenExtendedMiningChannelSuccess
	MethodNewMiningJob
	MethodUpdateChannel
	MethodUpdateChannelError
	MethodCloseChannel
	MethodSetExtranoncePrefix
	MethodSubmitSharesStandard
	MethodSubmitSharesExtended
	MethodSubmitSharesSuccess
	MethodSubmitSharesError
	MethodReserved
	MethodNewExtendedMiningJob
	MethodSetNewPrevHash
	MethodSetTarget
	MethodSetCustomMiningJob
	MethodSetCustomMiningJobSuccess
	MethodSetCustomMiningJobError
	MethodSetGroupChannel
)

// Job Declaration Protocol
const (
	MethodAllocateMiningJobToken            Method = 0x50
	MethodAllocateMiningJobTokenSuccess     Method = 0x51
	MethodProvideMissingTransactions        Method = 0x55
	MethodProvideMissingTransactionsSuccess Method = 0x56
	MethodDeclareMiningJob                  Method = 0x57
	MethodDeclareMiningJobSuccess           Method = 0x58
	MethodDeclareMiningJobError             Method = 0x59
	MethodPushSolution                      Method = 0x60
)

const (
	UnsupportedFeatureFlagsError Error = "unsupported-feature-flags"
	UnsupportedProtocolError     Error = "unsupported-protocol"
	ProtocolVersionMismatchError Error = "protocol-version-mismatch"
)

const (
	ExtensionTypeMinValid Extension = 0x4000
	ExtensionTypeMaxValid Extension = 0x7fff
	ExtensionTypeCore     Extension = 0
	// TODO: list valid extensions
	ExtensionNegotiaton                     Extension = 0x0001
	ExtensionWorkerSpecificHashrateTracking Extension = 0x0002
)
