package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestNewExtendedMiningJob(t *testing.T) {
	shouldBe := hexDec("00001f920100b0190b95010000000000000020010519f25b3c44389ffc09527689d9fd3b104ef425d934f4841b27a31c26d2de636bd56ba09ef8d29c50dff7debef84fa0139de4ca3db85f475fe5de357b8f927f0e923d1dc2a5718909478510d6e140ed7e2dd0c60b0319b89db789075f4c86bcd168534a4c36e5e1695165c64c1d1dc3c9fb4c66c671fd994a52e20eaf88459b330ddfe227c50e18eb23a0ead6c3ef4f20f9fa89d42d24b7256ea260601460bdcd7c0001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff590341500201e94a2f706f676f6c6f202d2076312e312e35202d20746573746e657434207375636b73206173732c206675636b20796f7520616c6c202d20646563656e7472616c697a65206f72206469652f076300feffffff020000000000000000266a24aa21a9edd00fcb727194d75dc197993f8ca4cd02c81ff40d48c81f96bab3961a6f2476a42a5d062a01000000225120ad6d194b43d3d249363724df8f961194112a18143e6e077475925bcf458f9dbb40500200")

	frame := stratumv2.Frame{}
	msg := stratumv2.NewExtendedMiningJob{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageNewExtendedMiningJob {
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

func TestSubmitSharesExtended(t *testing.T) {
	shouldBe := hexDec("00801b1c0000b0190b950000000001000000759253b49800a16a00000520030d0000")
	frame := stratumv2.Frame{}
	msg := stratumv2.SubmitSharesExtended{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSubmitSharesExtended {
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

func TestSubmitSharesSuccess(t *testing.T) {
	shouldBe := hexDec("00001c140000b0190b9500000000010000004336000000000000")

	frame := stratumv2.Frame{}
	msg := stratumv2.SubmitSharesSuccess{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSubmitSharesSuccess {
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

func TestSetTarget(t *testing.T) {
	shouldBe := hexDec("000021240000b0190b950726db55f99494d9693ad7079cbab4bf336c9c7524ef963b0817190000000000")

	frame := stratumv2.Frame{}
	msg := stratumv2.SetTarget{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSetTarget {
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

func TestSetNewPrevHash(t *testing.T) {
	shouldBe := hexDec("000020300000b0190b9501000000a4c97650f945f66c17b6575ad2578fb5e0c1236c59d4f4cc4c7dbdec000000009800a16a693d0319")

	frame := stratumv2.Frame{}
	msg := stratumv2.SetNewPrevHash{}
	if err := frame.Decode(shouldBe); err != nil {
		t.Logf("%+v", frame)
		t.Fatal(err.Error())
	}
	if frame.MessageType != stratumv2.MessageSetNewPrevHash {
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
