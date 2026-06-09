package stratumv2

// TODO
const FRAME_HEADER_LEN = 6
const MAX_CIPERTEXT_LEN = 65535
const MAC_LEN = 16
const MAX_PLAINTEXT_LEN = MAX_CIPERTEXT_LEN - MAC_LEN

func plaintextLen2CiphertextLen(l uint) int {
	rem := uint(0)
	rem = l % MAX_PLAINTEXT_LEN
	if rem > 0 {
		rem += MAC_LEN
	}
	return int(l/MAX_PLAINTEXT_LEN*MAX_CIPERTEXT_LEN + rem)
}

// TODO
type EncryptedFrame struct {
}
