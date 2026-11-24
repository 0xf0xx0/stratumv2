package stratumv2

import (
	"encoding/binary"
	"math"
)

var ble = binary.LittleEndian

const (
	// ProtocolVersion is the latest protocol version this package supports.
	ProtocolVersion          = 2
	CertificateFormatVersion = 0                                               // latest supported handshake certificate format version
	NoiseProtocolName        = "Noise_NX_Secp256k1+EllSwift_ChaChaPoly_SHA256" // use for the handshake
	// Serialized stratum-v2 body (payload) is split into 65519-byte chunks and encrypted to form 65535-bytes AEAD ciphertexts
	MaxPlaintextChunkSize = 65519
	MaxNoiseFrameSize     = 65535
	NoiseHeaderSize       = 22 // size of an encrypted header
	FrameHeaderSize       = 6  // size of a plaintext header
	MacLen                = 16
	MaxU24                = (2 << 23) - 1 // largest value that can be stored in a [U24]
)

var (
	maxNoiseNonce = uint64(math.Pow(2, 64)) - 1
)

const (
	MessageSetupConnection MessageType = iota
	MessageSetupConnectionSuccess
	MessageSetupConnectionError
	MessageChannelEndpointChanged
	MessageReconnect
)

// Protocols
const (
	MiningProtocol Protocol = iota
	JobDeclarationProtocol
	TemplateDistributionProtocol
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

// Template Distribution Protocol
const (
	MessageCoinbaseOutputConstraints     MessageType = 0x70
	MessageNewTemplate                   MessageType = 0x71
	MessageTemplateSetNewPrevHash        MessageType = 0x72
	MessageRequestTransactionData        MessageType = 0x73
	MessageRequestTransactionDataSuccess MessageType = 0x74
	MessageRequestTransactionDataError   MessageType = 0x75
	MessageSubmitSolution                MessageType = 0x76
)

// MessageTypeToString maps message type identifiers to their protocol message names.
var MessageTypeToString = map[MessageType]string{
	MessageSetupConnection:                   "SetupConnection",
	MessageSetupConnectionSuccess:            "SetupConnection.Success",
	MessageSetupConnectionError:              "SetupConnection.Error",
	MessageChannelEndpointChanged:            "ChannelEndpointChanged",
	MessageReconnect:                         "Reconnect",
	MessageOpenStandardMiningChannel:         "OpenStandardMiningChannel",
	MessageOpenStandardMiningChannelSuccess:  "OpenStandardMiningChannel.Success",
	MessageOpenMiningChannelError:            "OpenMiningChannel.Error",
	MessageOpenExtendedMiningChannel:         "OpenExtendedMiningChannel",
	MessageOpenExtendedMiningChannelSuccess:  "OpenExtendedMiningChannel.Success",
	MessageNewMiningJob:                      "NewMiningJob",
	MessageUpdateChannel:                     "UpdateChannel",
	MessageUpdateChannelError:                "UpdateChannel.Error",
	MessageCloseChannel:                      "CloseChannel",
	MessageSetExtranoncePrefix:               "SetExtranoncePrefix",
	MessageSubmitSharesStandard:              "SubmitSharesStandard",
	MessageSubmitSharesExtended:              "SubmitSharesExtended",
	MessageSubmitSharesSuccess:               "SubmitShares.Success",
	MessageSubmitSharesError:                 "SubmitShares.Error",
	MessageReserved:                          "Reserved",
	MessageNewExtendedMiningJob:              "NewExtendedMiningJob",
	MessageSetNewPrevHash:                    "SetNewPrevHash",
	MessageSetTarget:                         "SetTarget",
	MessageSetCustomMiningJob:                "SetCustomMiningJob",
	MessageSetCustomMiningJobSuccess:         "SetCustomMiningJob.Success",
	MessageSetCustomMiningJobError:           "SetCustomMiningJob.Error",
	MessageSetGroupChannel:                   "SetGroupChannel",
	MessageAllocateMiningJobToken:            "AllocateMiningJobToken",
	MessageAllocateMiningJobTokenSuccess:     "AllocateMiningJobToken.Success",
	MessageProvideMissingTransactions:        "ProvideMissingTransactions",
	MessageProvideMissingTransactionsSuccess: "ProvideMissingTransactions.Success",
	MessageDeclareMiningJob:                  "DeclareMiningJob",
	MessageDeclareMiningJobSuccess:           "DeclareMiningJob.Success",
	MessageDeclareMiningJobError:             "DeclareMiningJob.Error",
	MessagePushSolution:                      "PushSolution",
	MessageCoinbaseOutputConstraints:         "CoinbaseOutputConstraints",
	MessageNewTemplate:                       "NewTemplate",
	MessageTemplateSetNewPrevHash:            "SetNewPrevHash",
	MessageRequestTransactionData:            "RequestTransactionData",
	MessageRequestTransactionDataSuccess:     "RequestTransactionData.Success",
	MessageRequestTransactionDataError:       "RequestTransactionData.Error",
	MessageSubmitSolution:                    "SubmitSolution",
}

// StringToMessageType maps protocol message names to their message type identifiers.
// "SetNewPrevHash" is shared by Mining and Template Distribution and resolves to
// [MessageSetNewPrevHash], the Mining Protocol message.
var StringToMessageType = func() map[string]MessageType {
	out := make(map[string]MessageType, len(MessageTypeToString))
	for messageType, name := range MessageTypeToString {
		out[name] = messageType
	}
	out["SetNewPrevHash"] = MessageSetNewPrevHash
	return out
}()

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
