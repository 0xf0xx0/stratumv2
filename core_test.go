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
	b := hexDec("020001000000")
	m := stratumv2.SetupConnectionSuccess{}
	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}
