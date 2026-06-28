package stratumv2_test

import (
	"bytes"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestSetupConnectionEncDec(t *testing.T) {
	shouldBe := hexDec("000000500000000200020002000000055b3a3a315d1d160748617368666f7803486578296573702d6d696e65722d7636392e3432302d6576696c2d636c6f7365642d736f757263652d666f726b08626c757563687575")
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
	testEncode(t, stratumv2.ExtensionTypeCore, stratumv2.MessageSetupConnectionSuccess, bb, shouldBe)
}

func TestOpenExtendedMiningChannelEncDec(t *testing.T) {
	shouldBe := hexDec("000013690000010000003e62633170737165617a3068677a3571326c6370366e617977363970747a34657973396b616a6672756e6e363434657a38356b757877337973736338727570a5d4685300000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff0400")
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
