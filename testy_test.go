package stratumv2_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestBleh(t *testing.T) {
	h := sha256.New()
	b := []byte("/FOSS || GTFO/sv2go/")
	h.Write(b)
	r := make([]byte, 65535)
	rand.Read(r)
	h.Write(r)
	out := h.Sum(b)
	// out = append(out, r...)
	out = r
	f := stratumv2.Frame{
		ExtensionType: stratumv2.ExtensionTypeCore,
		MessageType:   stratumv2.MethodSetupConnection,
		MessageLength: uint32(len(out)),
		Payload:       out,
	}
	t.Log(f.MessageLength)
	x, err := f.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("%x", x)
}
