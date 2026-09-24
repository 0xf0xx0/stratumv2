package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"github.com/minio/sha256-simd"
)

func TestU256(t *testing.T) {
	target := &stratumv2.U256{}
	comp := &stratumv2.U256{}

	target.SetBytes(hexDec("00ff000000000000000000000000000000000000000000000000000000000000"))

	/// meets
	comp.SetBytes(hexDec("00ff000000000000000000000000000000000000000000000000000000000000"))
	if !target.IsMetBy(comp) {
		t.Error("should have met target")
	}

	/// exceeds
	comp.SetBytes(hexDec("ff00000000000000000000000000000000000000000000000000000000000000"))
	if !target.IsMetBy(comp) {
		t.Error("should have met target")
	}

	/// fails
	comp.SetBytes(hexDec("000000000000000000000000000000000000000000000000000000000000ff00"))
	if target.IsMetBy(comp) {
		t.Error("should have failed to meet target")
	}
}

// bench set and compare
func BenchmarkU256SetString(b *testing.B) {
	b1 := hexDec("00ff000000000000000000000000000000000000000000000000000000000000")

	u1 := &stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := &stratumv2.U256{}
		/// slowest path
		u2.SetString("000000000000000000000000000000000000000000000000000000000000ff00")
		ok := u1.IsMetBy(u2)
		if ok {
			b.Fatal("wtf")
		}
	}
}
func BenchmarkU256SetBytes(b *testing.B) {
	b1 := hexDec("00ff000000000000000000000000000000000000000000000000000000000000")
	b2 := hexDec("000000000000000000000000000000000000000000000000000000000000ff00")

	u1 := &stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := &stratumv2.U256{}
		/// slowest path
		u2.SetBytes(b2)
		ok := u1.IsMetBy(u2)
		if ok {
			b.Fatal("wtf")
		}
	}
}

func BenchmarkFrameEncode(b *testing.B) {
	m := &stratumv2.NewExtendedMiningJob{
		ChannelID: 0xdeadbeef,
		JobID:     0xbeefdead,
		MinTime:   []uint32{6666666},
		Version:   0xdeadbeef,
		MerklePath: []stratumv2.U256{
			sha256.Sum256([]byte("a")),
			sha256.Sum256([]byte("b")),
			sha256.Sum256([]byte("c")),
			sha256.Sum256([]byte("d")),
			sha256.Sum256([]byte("e")),
			sha256.Sum256([]byte("f")),
			sha256.Sum256([]byte("g")),
			sha256.Sum256([]byte("h")),
			sha256.Sum256([]byte("i")),
			sha256.Sum256([]byte("j")),
		},
		VersionRollingAllowed: false,
		/// simulate large coinbase
		CoinbasePrefix: []byte("aygtewsh4rewhstrdjtrszhgerwaghreshreshtresjhrdsgerah,34cweaio psfmlbrewcamnus filhxm,resngddi7 65urfvdb6 oni kuygbiuo;ficdkxmxd rsxnjhgboihlpu6v.btlv.98,zx5itc7 f,uyk ct7i8ueycxdkvp98;c578lptbon 87b9p r;t78;p tvy98 x5l8tgbiyusxw46sdx,u8kly,lh90o;8 bp;/_{)Uc"),
		CoinbaseSuffix: []byte("io;blkvgytu,kxcftu.liashfcvioewa'hgfvioewagvbfeuilwahfveiowqgvfbeuwiyalgfbewoisagfv.eriwul,afhneiwoa/g;fvbeuyk wsfzjmxdbeiowa;zhfeiuwlavfyuelwabfcneiow.AGBFWIOE'/QFHioewsz/;gfbeuia;/zfjpnjEOWP/GBUJIR;/DSNBGVIPO'WJq3nu-02wtn-98bv	4utydcuktuyyhjkiioiouifvh"),
	}
	bin, err := m.Encode()
	if err != nil {
		b.Fatal(err.Error())
	}
	f := &stratumv2.Frame{}
	f.MessageType = stratumv2.MessageNewExtendedMiningJob
	f.MessageLength = stratumv2.U24(len(bin))
	if f.ReadPayload(bin) != nil {
		b.Fatal("read failed")
	}
	/// FIXME: tlv encoding obliterates the speed
	// f.TLVs = append(f.TLVs, stratumv2.TLV{
	// 	ExtensionType: 69,
	// 	FieldType:     3,
	// 	Length:        uint16(len([]byte("UwU"))),
	// 	Value:         []byte("UwU"),
	// })
	for b.Loop() {
		_, err := f.Encode()
		if err != nil {
			b.Fatal(err.Error())
		}
	}
}
