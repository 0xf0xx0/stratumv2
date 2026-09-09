package stratumv2_test

import (
	"bytes"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestSetupConnectionEncDec(t *testing.T) {
	shouldBe := hexDec("0000002800000002000200040000000c33382e34392e3231322e39311d160662697461786506424d313337300000")
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
	compareFrameWithExpected(t, frame.ExtensionType, frame.MessageType, bb, shouldBe)
}
func TestSetupConnectionSuccessEncDec(t *testing.T) {
	shouldBe := hexDec("000001060000020000000000")
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
	compareFrameWithExpected(t, frame.ExtensionType, frame.MessageType, bb, shouldBe)
}

func TestOpenExtendedMiningChannelEncDec(t *testing.T) {
	shouldBe := hexDec("0000133100000100000006796970617865359e8253ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0200")
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
	compareFrameWithExpected(t, frame.ExtensionType, frame.MessageType, bb, shouldBe)
}
func TestOpenExtendedMiningChannelSuccessEncDec(t *testing.T) {
	shouldBe := hexDec("00001433000001000000b0190b950726db55f99494d9693ad7079cbab4bf336c9c7524ef963b0817190000000000030004950b19b000000000")
	frame := stratumv2.Frame{}
	msg := stratumv2.OpenExtendedMiningChannelSuccess{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageOpenExtendedMiningChannelSuccess {
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
	compareFrameWithExpected(t, frame.ExtensionType, frame.MessageType, bb, shouldBe)
}

func compareFrameWithExpected(t *testing.T, ExtensionType stratumv2.Extension, MessageType stratumv2.MessageType, bb, shouldBe []byte) {
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
		t.Fatal("encoded frame does not match original")
	}
}
