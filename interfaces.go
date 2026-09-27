package stratumv2

// MAYBE: merge into types.go

// [Frame] and all messages implement this interface
// TODO: io.reader interface
type Codable interface {
	Encode() ([]byte, error)
	Decode([]byte) error
	// DecodeFromReader(r io.Reader) error
	// MAYBE: String() string for pretty-printing?
}
