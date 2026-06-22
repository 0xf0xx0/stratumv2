package stratumv2

import "io"

type NoiseFrame struct {
	Header  []byte
	Payload []byte
	// MAC     [MacLen]byte
	Frame Frame
}

// Encrypt encrypts the header + payload.
func (n *NoiseFrame) Encrypt() ([]byte, error) {
	panic("UNIMPL")
}

// Decrypt decrypts the payload and stores it in [NoiseFrame.Frame]. It should be called after [NoiseFrame.DecryptHeader].
func (n *NoiseFrame) Decrypt(b []byte) error {
	panic("UNIMPL")
}

// DecryptHeader decrypts the header and stores it in [NoiseFrame.Frame]. It should be called before [NoiseFrame.Decrypt].
func (n *NoiseFrame) DecryptHeader(b []byte) error {
	panic("UNIMPL")
}

// TODO: decrypt header, read MessageLength, convert to encrypted len, read payload, decrypt
func (n *NoiseFrame) DecryptFromReader(r io.Reader) error {
	var err error

	header := make([]byte, 6)
	if _, err = r.Read(header); err != nil {
		return err
	}

	if err = n.DecryptHeader(header); err != nil {
		return err
	}
	n.Payload = make([]byte, plainTextLenToCipherTextLen(int(n.Frame.MessageLength)))
	if _, err = r.Read(n.Payload); err != nil {
		return err
	}
	if err = n.Decrypt(n.Payload); err != nil {
		return err
	}
	return nil
}

func plainTextLenToCipherTextLen(plainTextLen int) int {
	rem := plainTextLen % MaxPlainFrameSize
	if rem > 0 {
		rem += MacLen
	}
	return plainTextLen/MaxPlainFrameSize*MaxNoiseFrameSize + rem
}
