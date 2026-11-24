package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestMessageTypeStringMaps(t *testing.T) {
	/// SetNewPrevHash is shared by Mining and Template Distribution.
	if len(stratumv2.MessageTypeToString) != len(stratumv2.StringToMessageType)+1 {
		t.Fatalf("unexpected duplicate message names: %d types, %d names",
			len(stratumv2.MessageTypeToString), len(stratumv2.StringToMessageType))
	}
	for messageType, name := range stratumv2.MessageTypeToString {
		if got := messageType.String(); got != name {
			t.Errorf("MessageType(%#02x).String() = %q, want %q", uint8(messageType), got, name)
		}
		got, ok := stratumv2.StringToMessageType[name]
		if !ok {
			t.Errorf("StringToMessageType is missing %q", name)
			continue
		}
		if name == "SetNewPrevHash" {
			if got != stratumv2.MessageSetNewPrevHash {
				t.Errorf("StringToMessageType[%q] = %#02x, want Mining message %#02x", name, uint8(got), uint8(stratumv2.MessageSetNewPrevHash))
			}
		} else if got != messageType {
			t.Errorf("StringToMessageType[%q] = %#02x, want %#02x", name, uint8(got), uint8(messageType))
		}
	}
}
