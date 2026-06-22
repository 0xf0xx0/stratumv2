package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestSetupConnectionDecode(t *testing.T) {
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

func TestSetupConnectionSuccessDecode(t *testing.T) {
	b := hexDec("000001060000020001000000")
	f := stratumv2.Frame{}
	m := stratumv2.SetupConnectionSuccess{}
	if err := f.Decode(b); err != nil {
		t.Logf("%+v", f)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", f)
	t.Log(f.MessageType == stratumv2.MethodSetupConnectionSuccess)
	if err := m.Decode(f.Payload); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestSetupConnectionSuccessEncode(t *testing.T) {
	shouldBe := hexDec("000001060000020001000000")
	m := stratumv2.SetupConnectionSuccess{
		UsedVersion: 2,
		Flags:       1,
	}
	b, err := m.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("%x", b)
	f := stratumv2.Frame{
		ExtensionType: stratumv2.ExtensionTypeCore,
		MessageType:   stratumv2.MethodSetupConnectionSuccess,
		MessageLength: stratumv2.U24(len(b)),
		Payload:       b,
	}
	fb, err := f.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("%x, %d", fb, len(fb))
	t.Logf("%x", shouldBe)
}

func TestOpenExtendedMiningChannelDecode(t *testing.T) {
	b := hexDec("000013690000010000003e626331703074767134687572687377686d3670706b6579737836327675686e33363477776c3233786a32716a376130776477736339326c7333776630326ca5d46853ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0600")
	f := stratumv2.Frame{}
	if err := f.Decode(b); err != nil {
		t.Logf("%+v", f)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", f)
	m := stratumv2.OpenExtendedMiningChannel{}
	if err := m.Decode(f.Payload); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}
