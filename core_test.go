package stratumv2_test

import (
	"bytes"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestSetupConnectionEncDec(t *testing.T) {
	shouldBe := hexDec("0000002a00000002000200000000000e7075626c69632d706f6f6c2e696f050d0662697461786506424d313337300000")
	frame := stratumv2.Frame{}
	msg := stratumv2.SetupConnection{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSetupConnection {
		t.Fatal("message type mismatch")
	}
	if err := msg.Decode(frame.Payload); err != nil {
		t.Logf("%+v", msg)
		t.Fatal(err.Error())
	}

	/// enc
	bb, err := msg.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	testEncode(t, stratumv2.ExtensionTypeCore, stratumv2.MessageSetupConnection, bb, shouldBe)
}
func TestSetupConnectionSuccessEncDec(t *testing.T) {
	shouldBe := hexDec("000001060000020001000000")
	frame := stratumv2.Frame{}
	msg := stratumv2.SetupConnectionSuccess{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSetupConnectionSuccess {
		t.Fatal("message type mismatch")
	}
	if err := msg.Decode(frame.Payload); err != nil {
		t.Logf("%+v", msg)
		t.Fatal(err.Error())
	}

	/// enc
	bb, err := msg.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	testEncode(t, stratumv2.ExtensionTypeCore, stratumv2.MessageSetupConnectionSuccess, bb, shouldBe)
}

func TestOpenExtendedMiningChannelEncDec(t *testing.T) {
	shouldBe := hexDec("000013690000010000003e626331703074767134687572687377686d3670706b6579737836327675686e33363477776c3233786a32716a376130776477736339326c7333776630326ca5d46853ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0600")
	frame := stratumv2.Frame{}
	msg := stratumv2.OpenExtendedMiningChannel{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageOpenExtendedMiningChannel {
		t.Fatal("message type mismatch")
	}
	if err := msg.Decode(frame.Payload); err != nil {
		t.Logf("%+v", msg)
		t.Fatal(err.Error())
	}

	/// enc
	bb, err := msg.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("%+v", msg)
	testEncode(t, stratumv2.ExtensionTypeCore, stratumv2.MessageOpenExtendedMiningChannel, bb, shouldBe)
}

func testEncode(t *testing.T, ExtensionType stratumv2.Extension, MessageType stratumv2.MessageType, bb, shouldBe []byte) {
	frame := stratumv2.Frame{
		ExtensionType: ExtensionType,
		MessageType:   MessageType,
		MessageLength: stratumv2.U24(len(bb)),
		Payload:       bb,
	}
	fb, err := frame.Encode()
	if err != nil {
		t.Fatal(err.Error())
	}
	if !bytes.Equal(shouldBe, fb) {
		t.Logf("%x", shouldBe)
		t.Logf("%x", fb)
		t.Logf("%d", len(bb))
		t.Fatal("encoded frame does not match original")
	}
}
