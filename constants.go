package stratumv2

type Method = uint8

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
	UnsupportedFeatureFlagsError = "unsupported-feature-flags"
	UnsupportedProtocolError     = "unsupported-protocol"
	ProtocolVersionMismatchError = "protocol-version-mismatch"
)

// 3.4
type Extension = uint16

const (
	ExtensionTypeMinValid Extension = 0x4000
	ExtensionTypeMaxValid Extension = 0x7fff
	ExtensionTypeCore     Extension = 0
	// TODO: list valid extensions
	ExtensionNegotiaton                     Extension = 0x0001
	ExtensionWorkerSpecificHashrateTracking Extension = 0x0002
)
