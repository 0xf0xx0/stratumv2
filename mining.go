package stratumv2

import (
	"bytes"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// errors
const (
	UnknownUserError           Error = "unknown-user"
	MaxTargetOutOfRangeError   Error = "max-target-out-of-range"
	InvalidChannelIDError      Error = "invalid-channel-id"
	StaleShareError            Error = "stale-share"
	DifficultyTooLowError      Error = "difficulty-too-low"
	InvalidJobIDError          Error = "invalid-job-id"
	InvalidMiningJobTokenError Error = "invalid-mining-job-token"
)

// flags
const (
	// The downstream node requires standard jobs, and is unable to process extended jobs.
	RequiresStandardJobsFlag Flag = 0b001
	// If set to 1, the client notifies the server that it will send [SetCustomMiningJob] on this connection
	RequiresWorkSelectionFlag Flag = 0b010
	// The client requires version rolling for efficiency or correct operation and the
	// server MUST NOT send jobs which do not allow version rolling
	RequiresVersionRollingFlag Flag = 0b100
	// Upstream node will not accept any changes to the version field.
	// Note that if [RequiresVersionRollingFlag] was set in the [SetupConnection.Flags] field,
	// this bit MUST NOT be set.
	// Further, if this bit is set, extended jobs MUST NOT indicate support for version rolling.
	RequiresFixedVersionFlag Flag = 0b01
	// Upstream node will not accept opening of a standard channel
	RequiresExtendedChannelsFlag Flag = 0b10
)

type Bin32 = []byte

// This message requests to open a standard channel to the upstream node.
//
// After receiving a [SetupConnectionSuccess] message, the client SHOULD respond by opening channels on the connection.
// If no channels are opened within a reasonable period the server SHOULD close the connection for inactivity.
//
// Every client SHOULD start its communication with an upstream node by opening a channel,
// which is necessary for almost all later communication.
// The upstream node either passes opening the channel further or has enough local information to
// handle channel opening on its own (this is mainly intended for v1 proxies).
// Clients must also communicate information about their hashing power in order to
// receive well-calibrated job assignments.
type OpenStandardMiningChannel struct {
	// Client-specified identifier for matching responses from upstream server.
	// The value MUST be connection-wide unique and is not interpreted by the server.
	RequestID uint32
	// Unconstrained sequence of bytes.
	// Whatever is needed by upstream node to identify/authenticate the client,
	// e.g. "braiinstest.worker1".
	// Additional restrictions can be imposed by the upstream node (e.g. a pool).
	// It is highly recommended that UTF-8 encoding is used.
	UserIdentity string
	// [h/s] Expected hashrate of the device (or cumulative hashrate on the channel if
	// multiple devices are connected downstream) in h/s.
	// Depending on server's target setting policy, this value can be used for setting a
	// reasonable target for the channel.
	// Proxy MUST send 0.0f when there are no mining devices connected yet.
	NominalHashRate float32
	// Maximum target which can be accepted by the connected device or devices.
	// Server MUST accept the target or respond by sending [OpenMiningChannelError] message.
	MaxTarget chainhash.Hash
}

func (m *OpenStandardMiningChannel) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.
		Grow(64).
		AddU32(m.RequestID).
		AddStr255(m.UserIdentity).
		AddF32(m.NominalHashRate).
		AddU256(m.MaxTarget).
		Bytes()
}
func (m *OpenStandardMiningChannel) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.RequestID = r.ReadU32()
	m.UserIdentity = r.ReadStr255()
	m.NominalHashRate = r.ReadF32()
	m.MaxTarget = r.ReadU256()

	return r.Error()
}

// Sent as a response for opening a standard channel, if successful.
type OpenStandardMiningChannelSuccess struct {
	// Client-specified request ID from [OpenStandardMiningChannel] message,
	// so that the client can pair responses with open channel requests
	RequestID uint32
	// Newly assigned identifier of the channel,
	// stable for the whole lifetime of the connection,
	// e.g. it is used for broadcasting new jobs by [NewExtendedMiningJob]
	ChannelID uint32
	// Initial target for the mining channel
	Target chainhash.Hash
	// Bytes used as implicit first part of extranonce for the scenario when
	// extended job is served by the upstream node for a set of standard channels
	// that belong to the same group
	ExtranoncePrefix []byte
	// Group channel into which the new channel belongs. See [SetGroupChannel] for details.
	GroupChannelID uint32
}

func (m *OpenStandardMiningChannelSuccess) Encode() ([]byte, error) {
	out := NewBinaryBuilder()

	return out.
		Grow(72).
		AddU32(m.RequestID).
		AddU32(m.ChannelID).
		AddU256(m.Target).
		AddBin32(m.ExtranoncePrefix).
		AddU32(m.GroupChannelID).
		Bytes()
}
func (m *OpenStandardMiningChannelSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.RequestID = r.ReadU32()
	m.ChannelID = r.ReadU32()
	m.Target = r.ReadU256()
	m.ExtranoncePrefix = r.ReadBin32()
	m.GroupChannelID = r.ReadU32()

	return r.Error()
}

// Similar to [OpenStandardMiningChannel], but requests to open an extended channel instead of standard channel.
type OpenExtendedMiningChannel struct {
	OpenStandardMiningChannel
	// Minimum size of extranonce needed by the device/node.
	MinExtranonceSize uint16
}

func (m *OpenExtendedMiningChannel) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	// encode embedded struct furst
	b, err := m.OpenStandardMiningChannel.Encode()
	if err != nil {
		return nil, err
	}
	return out.Grow(72).AddBytes(b).
		AddU16(m.MinExtranonceSize).
		Bytes()
}
func (m *OpenExtendedMiningChannel) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.RequestID = r.ReadU32()
	m.UserIdentity = r.ReadStr255()
	m.NominalHashRate = r.ReadF32()
	m.MaxTarget = r.ReadU256()
	m.MinExtranonceSize = r.ReadU16()

	return r.Error()
}

// Sent as a response for opening an extended channel.
type OpenExtendedMiningChannelSuccess struct {
	OpenStandardMiningChannelSuccess
	ExtranonceSize uint16 // Extranonce size (in bytes) set for the channel
}

func (m *OpenExtendedMiningChannelSuccess) Encode() ([]byte, error) {
	out := NewBinaryBuilder()

	// encode embedded struct furst
	b, err := m.OpenStandardMiningChannelSuccess.Encode()
	if err != nil {
		return nil, err
	}

	return out.Grow(80).AddBytes(b).
		AddU16(m.ExtranonceSize).
		Bytes()
}
func (m *OpenExtendedMiningChannelSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.RequestID = r.ReadU32()
	m.ChannelID = r.ReadU32()
	m.Target = r.ReadU256()
	m.ExtranoncePrefix = r.ReadBin32()
	m.GroupChannelID = r.ReadU32()
	m.ExtranonceSize = r.ReadU16()

	return r.Error()
}

// Possible errors: [UnknownUserError], [MaxTargetOutOfRangeError]
type OpenMiningChannelError struct {
	RequestID uint32 // Client-specified request ID from [Open*MiningChannel] message
	ErrorCode Error  // Person-readable error code(s)
}

func (m *OpenMiningChannelError) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(24).AddU32(m.RequestID).AddStr255(string(m.ErrorCode)).Bytes()
}
func (m *OpenMiningChannelError) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.RequestID = r.ReadU32()
	m.ErrorCode = Error(r.ReadStr255())

	return r.Error()
}

// Client notifies the server about changes on the specified channel.
// If a client performs device/connection aggregation (i.e. it is a proxy),
// it MUST send this message when downstream channels change.
// This update can be debounced so that it is not sent more often than once in a second (for a very busy proxy).
//
// When MaxTarget is smaller than currently used maximum target for the channel,
// upstream node MUST reflect the client’s request (and send appropriate [SetTarget] message).
type UpdateChannel struct {
	ChannelID       uint32
	NominalHashRate float32 // See Open*Channel for details
	// Maximum target is changed by server by sending SetTarget.
	// This field is understood as device's request.
	// There can be some delay between UpdateChannel and corresponding SetTarget messages,
	// based on new job readiness on the server.
	MaxTarget chainhash.Hash
}

func (m *UpdateChannel) Encode() ([]byte, error) {
	out := NewBinaryBuilder()

	return out.Grow(40).AddU32(m.ChannelID).
		AddF32(m.NominalHashRate).
		AddU256(m.MaxTarget).
		Bytes()
}
func (m *UpdateChannel) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.NominalHashRate = r.ReadF32()
	m.MaxTarget = r.ReadU256()

	return r.Error()
}

// Sent only when [UpdateChannel] message is invalid.
// When it is accepted by the server, no response is sent back.
type UpdateChannelError struct {
	ChannelID uint32
	ErrorCode Error // Person-readable error code(s)
}

func (m *UpdateChannelError) Encode() ([]byte, error) {
	out := NewBinaryBuilder()

	return out.Grow(24).AddU32(m.ChannelID).
		AddStr255(string(m.ErrorCode)).
		Bytes()
}
func (m *UpdateChannelError) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.ErrorCode = Error(r.ReadStr255())

	return r.Error()
}

// Client sends this message when it ends its operation.
// The server MUST stop sending messages for the channel.
// A proxy MUST send this message on behalf of all opened channels from a downstream connection
// in case of downstream connection closure.
//
// If a proxy is operating in channel aggregating mode (translating downstream channels into
// aggregated extended upstream channels), it MUST send an [UpdateChannel] message when it receives
// [CloseChannel] or connection closure from a downstream connection.
// In general, proxy servers MUST keep the upstream node notified about the real state of the downstream channels.

// If ChannelID is addressing a group channel, all channels belonging to such group MUST be closed.
type CloseChannel struct {
	ChannelID  uint32
	ReasonCode string // Reason for closing the channel
}

func (m *CloseChannel) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(24).AddU32(m.ChannelID).AddStr255(m.ReasonCode).Bytes()
}
func (m *CloseChannel) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.ReasonCode = r.ReadStr255()
	return r.Error()
}

// Changes downstream node’s extranonce prefix.
// It is applicable for all jobs sent after this message on a given channel
// (both jobs provided by the upstream or jobs introduced by [SetCustomMiningJob] message).
// This message is applicable only for explicitly opened extended channels or standard channels
// (not group channels).
type SetExtranoncePrefix struct {
	ChannelID        uint32
	ExtranoncePrefix Bin32 // Bytes used as implicit first part of extranonce
}

func (m *SetExtranoncePrefix) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(32).AddU32(m.ChannelID).AddBin32(m.ExtranoncePrefix).Bytes()
}
func (m *SetExtranoncePrefix) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.ExtranoncePrefix = r.ReadBin32()

	return r.Error()
}

// Client sends result of its hashing work to the server.
type SubmitSharesStandard struct {
	ChannelID uint32
	Sequence  uint32 // Unique sequential identifier of the submit within the channel
	JobID     uint32 // Identifier of the job as provided by [NewMiningJob] or [NewExtendedMiningJob] message
	Nonce     uint32 // Nonce leading to the hash being submitted
	// The nTime field in the block header.
	// This MUST be greater than or equal to the [HeaderTimestamp] field in the latest
	// [SetNewPrevHash] message and lower than or equal to that value plus
	// the number of seconds since the receipt of that message.
	Time    uint32
	Version uint32 // Full nVersion field
}

func (m *SubmitSharesStandard) Encode() ([]byte, error) {
	out := NewBinaryBuilder()

	out.Grow(24).
		AddU32(m.ChannelID).
		AddU32(m.Sequence).
		AddU32(m.JobID).
		AddU32(m.Nonce).
		AddU32(m.Time).
		AddU32(m.Version)
	return out.Bytes()
}
func (m *SubmitSharesStandard) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.Sequence = r.ReadU32()
	m.JobID = r.ReadU32()
	m.Nonce = r.ReadU32()
	m.Time = r.ReadU32()
	m.Version = r.ReadU32()

	return r.Error()
}

// Only relevant for extended channels.
type SubmitSharesExtended struct {
	SubmitSharesStandard
	// Extranonce bytes which need to be added to coinbase to form a fully valid submission
	// (full coinbase = coinbase_tx_prefix + extranonce_prefix + extranonce + coinbase_tx_suffix).
	// The size of the provided extranonce MUST be equal to the negotiated extranonce size from channel opening.
	Extranonce Bin32
}

func (m *SubmitSharesExtended) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(48)

	b, err := m.SubmitSharesStandard.Encode()
	if err != nil {
		return nil, err
	}
	out.AddBytes(b).AddBin32(m.Extranonce)
	return out.Bytes()
}
func (m *SubmitSharesExtended) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.Sequence = r.ReadU32()
	m.JobID = r.ReadU32()
	m.Nonce = r.ReadU32()
	m.Time = r.ReadU32()
	m.Version = r.ReadU32()
	m.Extranonce = r.ReadBin32()

	return r.Error()
}

// Response to [SubmitSharesStandard] or [SubmitSharesExtended], accepting results from the miner.
// Because it is a common case that shares submission is successful, this response can be provided
// for multiple [SubmitShare*] messages aggregated together.
//
// The server does not have to double check that the sequence numbers sent by a client are actually increasing.
// It can simply use the last one received when sending a response.
// It is the client’s responsibility to keep the sequence numbers correct/useful.

// The illustration below assumes a mining server that acknowledges every 10 successful submissions,
// and that a [SetTarget] message was sent to increase the difficulty from `Da` to `Db` in the middle of the batch submission.

// Please note that [NewSubmitsAcceptedCount] and [NewSharesSum] carry meaning within the batch
// being acknowledged, and their respective counters MUST be reset when a new batch
// starts being processed.
type SubmitSharesSuccess struct {
	ChannelID               uint32
	LastSequenceNumber      uint32 // Most recent sequence number with a correct result
	NewSubmitsAcceptedCount uint32 // Count of new submits acknowledged within this batch
	NewSharesSum            uint64 // Sum of difficulty of shares acknowledged within this batch
}

func (m *SubmitSharesSuccess) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(24)

	out.AddU32(m.ChannelID).
		AddU32(m.LastSequenceNumber).
		AddU32(m.NewSubmitsAcceptedCount).
		AddU64(m.NewSharesSum)

	return out.Bytes()
}
func (m *SubmitSharesSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.LastSequenceNumber = r.ReadU32()
	m.NewSubmitsAcceptedCount = r.ReadU32()
	m.NewSharesSum = r.ReadU64()

	return r.Error()
}

// An error is immediately submitted for every incorrect submit attempt.
// In case the server is not able to immediately validate the submission,
// the error is sent as soon as the result is known.
// This delayed validation can occur when a miner gets faster updates about a new prevhash than
// the server does (see [SetNewPrevHash] message for details).
//
// Possible errors: [InvalidChannelIDError], [StaleShareError],
// [DifficultyTooLowError], [InvalidJobIDError]
type SubmitSharesError struct {
	ChannelID      uint32
	SequenceNumber uint32 // Submission sequence number for which this error is returned
	ErrorCode      Error  // Person-readable error code(s)
}

func (m *SubmitSharesError) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(24)

	out.AddU32(m.ChannelID).AddU32(m.SequenceNumber).AddStr255(string(m.ErrorCode))

	return out.Bytes()
}
func (m *SubmitSharesError) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.SequenceNumber = r.ReadU32()
	m.ErrorCode = Error(r.ReadStr255())
	return r.Error()
}

type NewMiningJob struct {
	ChannelID uint32
	JobID     uint32 // Identifier of the job as provided by [NewMiningJob] or [NewExtendedMiningJob] message
	// Smallest nTime value available for hashing for the new mining job.
	// A zero value indicates this is a future job to be activated once a [SetNewPrevHash] message is received with a matching [JobID].
	// This [SetNewPrevHash] message provides the new [PrevHash] and [MinTime].
	// If the [MinTime] value is set, this mining job is active and miner must start mining on it immediately.
	// In this case, the new mining job uses the [SetNewPrevHash.PrevHash] from the last received [SetNewPrevHash] message.
	MinTime []uint32
	// Valid version field that reflects the current network consensus.
	// The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node.
	// The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value.
	Version    uint32
	MerkleRoot chainhash.Hash // Merkle root field as used in the bitcoin block header
}

func (m *NewMiningJob) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(72)

	out.AddU32(m.ChannelID).
		AddU32(m.JobID).
		AddOptionT(U32Sequence(m.MinTime)).
		AddU32(m.Version).
		AddU256(m.MerkleRoot)

	return out.Bytes()
}
func (m *NewMiningJob) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.JobID = r.ReadU32()
	m.MinTime = []uint32(r.ReadOptionT(make(U32Sequence, 0)).(U32Sequence))
	m.Version = r.ReadU32()
	m.MerkleRoot = r.ReadU256()

	return r.Error()
}

// (Extended and group channels only)
//
// For an extended channel: The whole search space of the job is owned by the specified channel.
// If the [MinTime] field is set to some nTime, the client MUST start to mine on the new job as soon
// as possible after receiving this message.
//
// For a group channel: This acts as a broadcast message that distributes work to all channels under
// the same group with one single message, instead of one per channel.
//
// The proxy MAY transform this multicast variant for downstream standard channels into [NewMiningJob]
// messages by computing the derived Merkle root for them. A proxy MUST translate the message into
// [NewMiningJob] for all downstream standard channels belonging to the group in case
// the [SetupConnection] message had the [RequiresStandardJobsFlag] flag set
// (intended and expected behavior for end mining devices).
//
// *The full coinbase is constructed by inserting one of the following:
//
// - For a standard channel: [ExtranoncePrefix]
//
// - For an extended channel: `[ExtranoncePrefix] + [Extranonce] (=N bytes)`, where `N` is the negotiated extranonce space for the channel ([OpenExtendedMiningChannelSuccess.ExtranonceSize])
//
// *If the original coinbase is a SegWit transaction, [CoinbasePrefix] and [CoinbaseSuffix] MUST be
// stripped of BIP141 fields (marker, flag, witness count, witness length and witness reserved value).
//
// The merkle root is then calculated as follows:
//
//	# Build the coinbase transaction
//	coinbase_tx = concatenate(
//	    coinbase_tx_prefix,
//	    extranonce_prefix,
//	    extranonce, # null if standard channel
//	    coinbase_tx_suffix
//	)
//
//	# txid of the coinbase transaction (not wtxid, as coinbase_tx_prefix and coinbase_tx_suffix were stripped of BIP141)
//	coinbase_txid = SHA256(SHA256(coinbase_tx))
//
//	# Compute the Merkle root by folding over the Merkle path
//	raw_merkle_root = coinbase_txid
//	for each merkle_leaf in merkle_path:
//	    data = concatenate(raw_merkle_root, merkle_leaf as little_endian_bytes)
//	    raw_merkle_root = SHA256(SHA256(data))
//
//	# Interpret the final 32-byte hash as a 256-bit integer in little-endian form
//	merkle_root = Uint256(little_endian_bytes = raw_merkle_root)
type NewExtendedMiningJob struct {
	ChannelID uint32
	JobID     uint32 // Identifier of the job as provided by [NewMiningJob] or [NewExtendedMiningJob] message
	// Smallest nTime value available for hashing for the new mining job.
	// A zero value indicates this is a future job to be activated once a [SetNewPrevHash] message is received with a matching [JobID].
	// This [SetNewPrevHash] message provides the new [PrevHash] and [MinTime].
	// If the [MinTime] value is set, this mining job is active and miner must start mining on it immediately.
	// In this case, the new mining job uses the [SetNewPrevHash.PrevHash] from the last received [SetNewPrevHash] message.
	MinTime []uint32
	// Valid version field that reflects the current network consensus.
	// The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node.
	// The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value.
	Version    uint32
	MerklePath []chainhash.Hash // Merkle path hashes ordered from deepest
	// If set to True, the general purpose bits of version (as specified in BIP320) can be
	// freely manipulated by the downstream node.
	// The downstream node MUST NOT rely on the upstream node to set the BIP320 bits to any particular value.
	// If set to False, the downstream node MUST use version as it is defined by this message.
	VersionRollingAllowed bool
	CoinbasePrefix        []byte // Prefix part of the coinbase transaction*
	CoinbaseSuffix        []byte // Suffix part of the coinbase transaction*
}

func (m *NewExtendedMiningJob) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(120)

	out.AddU32(m.ChannelID).
		AddU32(m.JobID).
		AddOptionT(U32Sequence(m.MinTime)).
		AddU32(m.Version).
		AddBool(m.VersionRollingAllowed).
		AddSeq255(U256Sequence(m.MerklePath)).
		AddBin64K(m.CoinbasePrefix).
		AddBin64K(m.CoinbaseSuffix)

	return out.Bytes()
}
func (m *NewExtendedMiningJob) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.JobID = r.ReadU32()
	m.MinTime = []uint32(r.ReadOptionT(U32Sequence{}).(U32Sequence))
	m.Version = r.ReadU32()
	m.VersionRollingAllowed = r.ReadBool()
	m.MerklePath = []chainhash.Hash(r.ReadSeq255(U256Sequence{}).(U256Sequence))
	m.CoinbasePrefix = r.ReadBin64K()
	m.CoinbaseSuffix = r.ReadBin64K()

	return r.Error()
}

// Prevhash is distributed whenever a new block is detected in the network by an upstream node or when a new downstream opens a channel.
//
// This message MAY be shared by all downstream nodes (sent only once to each group channel). Clients MUST immediately start to mine on the provided prevhash. When a client receives this message, only the job referenced by Job ID is valid. The remaining jobs already queued by the client have to be made invalid.
//
// Note: There is no need for block height in this message.
type SetNewPrevHash struct {
	ChannelID uint32
	// ID of a job that is to be used for mining with this prevhash.
	// A pool may have provided multiple jobs for the next block height
	// (e.g. an empty block or a block with transactions that are complementary to
	// the set of transactions present in the current block template).
	JobID    uint32
	PrevHash chainhash.Hash // Previous block’s hash, block header field
	MinTime  uint32         // Smallest nTime value available for hashing
	Bits     uint32         // Block header field
}

func (m *SetNewPrevHash) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(48)

	out.AddU32(m.ChannelID).
		AddU32(m.JobID).
		AddU256(m.PrevHash).
		AddU32(m.MinTime).
		AddU32(m.Bits)

	return out.Bytes()
}
func (m *SetNewPrevHash) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.JobID = r.ReadU32()
	m.PrevHash = r.ReadU256()
	m.MinTime = r.ReadU32()
	m.Bits = r.ReadU32()
	return r.Error()
}

// Can be sent only on extended or group channel.
// If the group channel contains standard channels, the server MUST ignore those.
//
// [SetupConnection.Flags] MUST contain [REQUIRES_WORK_SELECTION] flag
// (work selection feature successfully declared).
//
// This message signals that JDC expects to be rewarded for working on a Custom Job.
type SetCustomMiningJob struct {
	ChannelID      uint32
	RequestID      uint32 // Client-specified identifier for pairing responses
	MiningJobToken []byte // Token provided by JDS which uniquely identifies the Custom Job that JDC has declared. See the Job Declaration Protocol for more details.
	// Valid version field that reflects the current network consensus.
	// The general purpose bits (as specified in BIP320) can be freely manipulated by the downstream node.
	Version          uint32
	PrevHash         chainhash.Hash // Previous block’s hash, found in the block header field
	MinTime          uint32         // Smallest nTime value available for hashing
	Bits             uint32         // Block header field
	CoinbaseVersion  uint32         // The coinbase transaction nVersion field
	CoinbasePrefix   []byte         // Up to 8 bytes (not including the length byte) which are to be placed at the beginning of the coinbase field in the coinbase transaction.
	CoinbaseSequence uint32         // The coinbase transaction input's nSequence field
	// Outputs of the coinbase transaction.
	// CompactSize‑prefixed array of consensus‑serialized outputs.
	CoinbaseOutputs  []wire.TxOut
	CoinbaseLocktime uint32           // The locktime field in the coinbase transaction
	MerklePath       []chainhash.Hash // Merkle path hashes ordered from deepest
}

func (m *SetCustomMiningJob) Encode() ([]byte, error) {
	coinbaseOutputs := make([]byte, 0, len(m.CoinbaseOutputs)*256)
	for _, txout := range m.CoinbaseOutputs {
		var buf bytes.Buffer
		buf.Grow(txout.SerializeSize())
		wire.WriteTxOut(&buf, uint32(wire.LatestEncoding), int32(m.CoinbaseVersion), &txout)
		coinbaseOutputs = append(coinbaseOutputs, buf.Bytes()...)
	}

	out := NewBinaryBuilder().
		Grow(2048).
		AddU32(m.ChannelID).
		AddU32(m.RequestID).
		AddBin255(m.MiningJobToken).
		AddU32(m.Version).
		AddU256(m.PrevHash).
		AddU32(m.MinTime).
		AddU32(m.Bits).
		AddU32(m.CoinbaseVersion).
		AddBin255(m.CoinbasePrefix).
		AddU32(m.CoinbaseSequence).
		AddBin64K(coinbaseOutputs).
		AddU32(m.CoinbaseLocktime).
		AddSeq255(U256Sequence(m.MerklePath))
	return out.Bytes()
}
func (m *SetCustomMiningJob) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.RequestID = r.ReadU32()
	m.MiningJobToken = r.ReadBin255()
	m.Version = r.ReadU32()
	m.PrevHash = r.ReadU256()
	m.MinTime = r.ReadU32()
	m.Bits = r.ReadU32()
	m.CoinbaseVersion = r.ReadU32()
	m.CoinbasePrefix = r.ReadBin255()
	m.CoinbaseSequence = r.ReadU32()

	/// FIXME: encoding

	// outputs := r.ReadBin64K()
	// l, err := wire.ReadVarIntBuf(r, uint32(wire.LatestEncoding), outputs)
	//m.CoinbaseOutputs = make([]wire.TxOut, 0, l)
	// for i := uint64(0); i < l; i++ {
	// txout := &wire.TxOut{}
	// wire.ReadTxOut(r, uint32(wire.LatestEncoding), int32(m.CoinbaseVersion), txout)
	// m.CoinbaseOutputs = append(m.CoinbaseOutputs, *txout)
	// }
	m.CoinbaseLocktime = r.ReadU32()
	return r.Error()
}

// Response from the Pool when it accepts the custom mining job.
//
// Up until receiving this message (and after having all the necessary information to start hashing),
// the miner SHOULD start hashing and buffer the work optimistically.
//
// This message acts as a commitment from the Pool to rewarding this job.
// In case the Pool does not commit (either by timeout, or responding with [SetCustomMiningJobError]),
// the miner SHOULD fall back to a different Pool (or solo).
//
// After receiving it, the miner can start submitting shares for this job immediately
// (by using the [JobID] provided within this response).
type SetCustomMiningJobSuccess struct {
	ChannelID uint32
	// Client-specified identifier for pairing responses.
	// Value from the request MUST be provided by upstream in the response message.
	RequestID uint32
	JobID     uint32 // Server’s identification of the mining job
}

func (m *SetCustomMiningJobSuccess) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(12).AddU32(m.ChannelID).
		AddU32(m.RequestID).
		AddU32(m.JobID).Bytes()
}
func (m *SetCustomMiningJobSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.RequestID = r.ReadU32()
	m.JobID = r.ReadU32()
	return r.Error()
}

// Possible errors: [InvalidChannelIDError], [InvalidMiningJobTokenError]
type SetCustomMiningJobError struct {
	ChannelID uint32
	// Client-specified identifier for pairing responses.
	// Value from the request MUST be provided by upstream in the response message.
	RequestID uint32
	ErrorCode Error // Reason why the custom job has been rejected
}

func (m *SetCustomMiningJobError) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(16 + 255).AddU32(m.ChannelID).
		AddU32(m.RequestID).
		AddStr255(string(m.ErrorCode)).Bytes()
}
func (m *SetCustomMiningJobError) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.RequestID = r.ReadU32()
	m.ErrorCode = Error(r.ReadStr255())
	return r.Error()
}

// The server controls the submission rate by adjusting the difficulty target on a specified channel.
// All submits leading to hashes higher than the specified target will be rejected by the server.
//
// Maximum target is valid until the next SetTarget message is sent and is applicable for all
// jobs received on the channel in the future or already received with an empty [MinTime].
// The message is not applicable for already received jobs with MinTime=nTime,
// as their maximum target remains stable.
//
// When SetTarget is sent to a group channel, the maximum target is applicable to all channels in the group.
type SetTarget struct {
	ChannelID uint32
	MaxTarget U256 // Maximum value of produced hash that will be accepted by a server to accept shares
}

func (m *SetTarget) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(36).AddU32(m.ChannelID).
		AddU256(chainhash.Hash(m.MaxTarget)).Bytes()
}
func (m *SetTarget) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.ChannelID = r.ReadU32()
	m.MaxTarget = U256(r.ReadU256())
	return r.Error()
}

// The group channel is used mainly for efficient job distribution to multiple mining channels (either standard and/or extended).

// If we want to allow different jobs to be served to different mining channels
// (e.g. because of different BIP 8 version bits) and still be able to distribute the work by
// sending [NewExtendedMiningJob] instead of a repeated [NewMiningJob] and/or [NewExtendedMiningJob],
// we need a more fine-grained grouping for standard channels.
//
// This message associates a set of mining channels with a group channel.
// A channel (identified by particular ID) becomes a group channel when it is used by this message as [GroupChannelID].
// The server MUST ensure that a group channel has a unique channel ID within one connection.
// Channel reinterpretation is not allowed.
//
// This message can be sent only to connections that don’t have [RequiresStandardJobsFlag] flag in [SetupConnection].
type SetGroupChannel struct {
	GroupChannelID uint32   // Identifier of the group where the standard or extended channel belongs
	ChannelIDs     []uint32 // A sequence of opened standard or extended channel IDs, for which the group channel is being redefined
}

func (m *SetGroupChannel) Encode() ([]byte, error) {
	out := NewBinaryBuilder()
	return out.Grow(32).AddU32(m.GroupChannelID).
		AddSeq64K(U32Sequence(m.ChannelIDs)).Bytes()
}
func (m *SetGroupChannel) Decode(b []byte) error {
	r := NewBinaryReader(b)

	m.GroupChannelID = r.ReadU32()
	l := r.ReadU16()
	m.ChannelIDs = make([]uint32, 0, l)
	for range l {
		m.ChannelIDs = append(m.ChannelIDs, r.ReadU32())
	}
	return r.Error()
}
