package stratumv2

// flags
const (
	// When the bit is set, JDC agrees to reveal the template's txdata
	// via [DeclareMiningJob] and [ProvideMissingTransactions].
	// Essentially sets Coinbase-only vs Full-Template mode.
	DeclareTxDataFlag Flag = 0b00
)

// A request to get an identifier for a future-submitted mining job.
// Rate limited to a rather slow rate and only available on connections
// where this has been negotiated.
// Otherwise, only MiningJobToken(s) from [AllocateMiningJobTokenSuccess] are valid.
type AllocateMiningJobToken struct {
	// Opaque byte sequence used by the pool to identify/authenticate the client, e.g. "username".
	// Its content is not interpreted by the protocol; the pool MAY impose additional restrictions.
	UserIdentity string
	RequestID    uint32 // Unique identifier for pairing the response.
}

func (m *AllocateMiningJobToken) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(len(m.UserIdentity) + 5).
		AddStr255(m.UserIdentity).
		AddU32(m.RequestID).
		Bytes()
}
func (m *AllocateMiningJobToken) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.UserIdentity = r.ReadStr255()
	m.RequestID = r.ReadU32()
	return r.Error()
}

// The Server MUST NOT change the value of CoinbaseOutputMaxAdditionalSize between
// [AllocateMiningJobTokenSuccess] messages unless a change in the pool’s configuration actually requires it.
// Notably, a pool whose required coinbase output space changes regularly SHOULD instead advertise
// the maximum of all such sizes as the CoinbaseOutputMaxAdditionalSize value, rather than varying it per message.
//
// The following rules apply to [AllocateMiningJobTokenSuccess.CoinbaseTxOutputs]:
//   - JDS MUST reserve the first output with a locking script where the pool payout will go.
//     While this output is initially set with a 0 amount of sats, this convention designates
//     this locking script as the pool payout output.
//   - JDS MAY add more zero-valued outputs in addition to the pool payout output.
//
// Once JDC receives [AllocateMiningJobTokenSuccess], the following rules apply to the subsequent
// [DeclareMiningJob.CoinbaseTxSuffix] (if under Full-Template mode) and
// [SetCustomMiningJob.CoinbaseOutputs] (under both Full-Template and Coinbase-only modes) message fields:
//   - JDC MUST allocate sats into the pool payout output in order to qualify for pooled mining rewards.
//     JDS and Pool SHOULD reject custom jobs that fail to do so.
//   - JDC MAY add more zero-valued outputs in addition to the ones established by JDS.
//   - JDC MAY add more non-zero-valued outputs in addition to the ones established by JDS.
//     In doing so, the template revenue is not fully allocated to the designated pool payout output,
//     so Pool MAY pay proportionally smaller rewards for this job.
//   - JDC MAY arbitrarily reorder the outputs to something different from the original ordering
//     of [AllocateMiningJobTokenSuccess.CoinbaseTxOutputs].
//   - Under Full-Template mode, the order of the outputs under [DeclareMiningJob.CoinbaseTxSuffix]
//     and [SetCustomMiningJob.CoinbaseOutputs] MUST remain the same, even if they differ from
//     the original [AllocateMiningJobTokenSuccess.CoinbaseTxOutputs].
//
// In summary, JDC is free to add more outputs and shuffle them under any arbitrary ordering scheme
// (while respecting BIP141).
type AllocateMiningJobTokenSuccess struct {
	RequestID uint32 // Unique identifier for pairing the response.
	// Token that makes the client eligible for committing a mining job for approval/transaction declaration
	// or for identifying custom mining job on mining connection.
	MiningJobToken B0_255
	// Bitcoin transaction outputs added by the pool.
	// CompactSize-prefixed array of consensus-serialized outputs.
	CoinbaseTxOutputs B0_64K
}

func (m *AllocateMiningJobTokenSuccess) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(len(m.MiningJobToken) + len(m.CoinbaseTxOutputs) + 7).
		AddU32(m.RequestID).
		AddBin255(m.MiningJobToken).
		AddBin64K(m.CoinbaseTxOutputs).
		Bytes()
}
func (m *AllocateMiningJobTokenSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.MiningJobToken = r.ReadB0_255()
	m.CoinbaseTxOutputs = r.ReadB0_64K()
	return r.Error()
}

// Only used in Full-Template mode.
//
// A request sent by JDC that proposes a selected set of transactions to JDS.
//
// Differently from [NewExtendedMiningJob], if the original coinbase is a SegWit transaction,
// [DeclareMiningJob.CoinbaseTxPrefix] and [DeclareMiningJob.CoinbaseTxSuffix] MUST NOT be stripped
// of BIP141 fields (marker, flag, witness count, witness length and witness reserved value).
type DeclareMiningJob struct {
	// Unique identifier for pairing the response.
	RequestID        uint32
	MiningJobToken   B0_255 // Previously reserved mining job token received by [AllocateMiningJobTokenSuccess].
	Version          uint32 // Version header field. To be later modified by BIP323-consistent changes.
	CoinbaseTxPrefix B0_64K // Serialized bytes representing the initial part of the coinbase transaction (not including extranonce).
	CoinbaseTxSuffix B0_64K // Serialized bytes representing the final part of the coinbase transaction (after extranonce).
	// List of wtxids of the transactions contained in the template.
	// The list MUST be in block order, which is the order of [RequestTransactionDataSuccess.TransactionList].
	// JDS checks the list against its mempool and requests missing txs via [ProvideMissingTransactions].
	// Does not include the coinbase transaction (as there is no corresponding full data for it yet).
	WTxidList  []U256 // SEQ0_64K
	ExcessData B0_64K // Extra data which the Pool may require to validate the work (as defined in the Template Distribution Protocol).
}

func (m *DeclareMiningJob) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(len(m.MiningJobToken) + len(m.CoinbaseTxPrefix) + len(m.CoinbaseTxSuffix) + len(m.ExcessData) + len(m.WTxidList)*32 + 17).
		AddU32(m.RequestID).
		AddBin255(m.MiningJobToken).
		AddU32(m.Version).
		AddBin64K(m.CoinbaseTxPrefix).
		AddBin64K(m.CoinbaseTxSuffix)
	out = AddSeq64K(out, m.WTxidList, (*BinaryBuilder).AddU256)
	out.AddBin64K(m.ExcessData)
	return out.Bytes()
}
func (m *DeclareMiningJob) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.MiningJobToken = r.ReadB0_255()
	m.Version = r.ReadU32()
	m.CoinbaseTxPrefix = r.ReadB0_64K()
	m.CoinbaseTxSuffix = r.ReadB0_64K()
	m.WTxidList = ReadSeq64K(r, (*BinaryReader).ReadU256)
	m.ExcessData = r.ReadB0_64K()
	return r.Error()
}

// A response sent by JDS acknowledging some Custom Job declaration.
//
// JDS MAY request txdata via [ProvideMissingTransactions] before making this commitment.
//
// Since JDS could be third party (not necessarily integrated to Pool),
// [DeclareMiningJobSuccess.NewMiningJobToken] MAY carry a cryptographic commitment from JDS where:
//   - JDS acknowledges that the template declared under [DeclareMiningJob.MiningJobToken] is valid.
//   - It signals to JDC that it should use [SetCustomMiningJob.MiningJobToken] set to
//     [DeclareMiningJobSuccess.NewMiningJobToken] when declaring Custom Jobs to Pool as a way to prove
//     it went through the Full-Template declaration process.
type DeclareMiningJobSuccess struct {
	RequestID         uint32 // Identifier of the original request.
	NewMiningJobToken B0_255 // Unique custom work identifier.
}

func (m *DeclareMiningJobSuccess) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(len(m.NewMiningJobToken) + 5).
		AddU32(m.RequestID).
		AddBin255(m.NewMiningJobToken).
		Bytes()
}
func (m *DeclareMiningJobSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.NewMiningJobToken = r.ReadB0_255()
	return r.Error()
}

// A response sent by JDS rejecting some Custom Job declaration.
//
// This SHOULD be a trigger for fallback into some other Pool+JDS or solo mining.
type DeclareMiningJobError struct {
	RequestID    uint32 // Identifier of the original request.
	ErrorCode    string // Human-readable error code(s).
	ErrorDetails B0_64K // Optional data providing further details to given error.
}

func (m *DeclareMiningJobError) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(len(m.ErrorCode) + len(m.ErrorDetails) + 4).
		AddU32(m.RequestID).
		AddStr255(m.ErrorCode).
		AddBin64K(m.ErrorDetails).
		Bytes()
}
func (m *DeclareMiningJobError) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.ErrorCode = r.ReadStr255()
	m.ErrorDetails = r.ReadB0_64K()
	return r.Error()
}

// Only used in Full-Template mode.
//
// If [DeclareMiningJob] includes some transactions that JDS's mempool has not yet seen,
// then JDS MUST request that JDC provides those missing ones.
type ProvideMissingTransactions struct {
	RequestID uint32 // Identifier of the original [DeclareMiningJob] request.
	// A list of unrecognized transactions that need to be supplied by the Job Declarator in full.
	// They are specified by their position in the original [DeclareMiningJob] message,
	// 0-indexed not including the coinbase transaction.
	UnknownTxPositionList []uint16
}

func (m *ProvideMissingTransactions) Encode() ([]byte, error) {
	out := NewBinaryBuilder().Grow(4 + len(m.UnknownTxPositionList)*2).AddU32(m.RequestID)
	out = AddSeq64K(out, m.UnknownTxPositionList, (*BinaryBuilder).AddU16)
	return out.Bytes()
}

func (m *ProvideMissingTransactions) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.UnknownTxPositionList = ReadSeq64K(r, (*BinaryReader).ReadU16)
	return r.Error()
}

// This is a message to push transactions that the server did not recognize
// and requested them to be supplied in [ProvideMissingTransactions].
type ProvideMissingTransactionsSuccess struct {
	RequestID uint32 // Identifier of the original [DeclareMiningJob] request.
	// List of full transactions as requested by [ProvideMissingTransactions],
	// in the order they were requested in [ProvideMissingTransactions].
	// Each transaction MUST be relayed exactly as received from the Template Provider
	// via [RequestTransactionDataSuccess], without parsing or re-encoding;
	// in practice this is the p2p network serialization, including witness data for SegWit transactions (BIP144).
	TxList []B0_16M // SEQ0_64K
}

func (m *ProvideMissingTransactionsSuccess) Encode() ([]byte, error) {
	/// guess tx len
	/// MAYBE: find median on-chain tx size?
	out := NewBinaryBuilder().Grow(255*len(m.TxList) + 4).
		AddU32(m.RequestID)
	AddSeq64K(out, m.TxList, (*BinaryBuilder).AddBin16M)
	return out.Bytes()
}

func (m *ProvideMissingTransactionsSuccess) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.RequestID = r.ReadU32()
	m.TxList = ReadSeq64K(r, (*BinaryReader).ReadB0_16M)
	return r.Error()
}

// Only used in Full-Template mode.
//
// Sent by JDC as soon as a valid block is found, so that it can be propagated also by JDS.
//
// [PushSolution] is only guaranteed to be valid for the most recent [DeclareMiningJobSuccess]
// that JDS has sent on the same connection.
//
// When receiving [PushSolution], JDS MUST attempt to reconstruct and propagate the block
// using the job data associated with its most recently sent [DeclareMiningJobSuccess].
//
// JDS MAY try to reconstruct and propagate the block using job data associated with other
// recently sent [DeclareMiningJobSuccess], but if the solution does not correspond to the last
// declared job, JDS is not expected to propagate it.
//
// Regardless of JDS-side propagation, the block is always transmitted to the network by JDC
// through the [SubmitSolution] message in the Template Distribution Protocol.
//
// In this way, the protocol encourages valid solutions to be immediately propagated on both
// client and server sides, decreasing the chance of the block being orphaned by the network.
type PushSolution struct {
	// Extranonce bytes which need to be added to coinbase to form a fully valid submission.
	// This is the full extranonce.
	Extranonce B0_32
	PrevHash   U256   // Hash of the last block.
	Nonce      uint32 // Nonce leading to the hash being submitted.
	Ntime      uint32 // The nTime field in the block header.
	Nbits      uint32 // The nBits field in the block header.
	Version    uint32 // Version header field.
}

func (m *PushSolution) Encode() ([]byte, error) {
	return NewBinaryBuilder().Grow(len(m.Extranonce) + 80).
		AddBin32(m.Extranonce).
		AddU256(m.PrevHash).
		AddU32(m.Nonce).
		AddU32(m.Ntime).
		AddU32(m.Nbits).
		AddU32(m.Version).
		Bytes()
}

func (m *PushSolution) Decode(b []byte) error {
	r := NewBinaryReader(b)
	m.Extranonce = r.ReadB0_32()
	m.PrevHash = r.ReadU256()
	m.Nonce = r.ReadU32()
	m.Ntime = r.ReadU32()
	m.Nbits = r.ReadU32()
	m.Version = r.ReadU32()
	return r.Error()
}
