package stratumv2_test

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestBleh(t *testing.T) {
	h := sha256.New()
	b := []byte("/FOSS || GTFO/stratumv2/")
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
	// t.Log(f.MessageLength)
	_, err := f.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	// t.Logf("%x", x)
}

func TestFrameSetupConnectionDecode(t *testing.T) {
	b := hexDec("0000002a00000002000200000000000e7075626c69632d706f6f6c2e696f050d0662697461786506424d313337300000")
	f := stratumv2.Frame{}
	if err := f.Decode(b); err != nil {
		t.Logf("%+v", f)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", f)
	m := stratumv2.SetupConnection{}
	if err := m.Decode(f.Payload); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestSetupConnectionSuccess(t *testing.T) {
	b := hexDec("020001000000")
	m := stratumv2.SetupConnectionSuccess{}
	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func hexDec(s string) []byte {
	x, _ := hex.DecodeString(s)
	return x
}
