package stratumv2_test

import (
	"math/big"
	"math/rand"
	"strconv"
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"github.com/minio/sha256-simd"
)

func TestU256(t *testing.T) {
	target := stratumv2.U256{}
	compar := stratumv2.U256{}

	target.SetString("00ff000000000000000000000000000000000000000000000000000000000000")

	/// meets (equal)
	compar.SetString("00ff000000000000000000000000000000000000000000000000000000000000")
	if !target.IsMetBy(compar) {
		t.Error("should have met target")
	}

	/// meets (less than)
	compar.SetString("000000000000000000000000000000000000000000000000000000000000ff00")
	if !target.IsMetBy(compar) {
		t.Error("should have met target")
	}

	/// fails
	compar.SetString("ff00000000000000000000000000000000000000000000000000000000000000")
	if target.IsMetBy(compar) {
		t.Error("should have failed to meet target")
	}

	/// fails (shared nonzero prefix, hash > target)
	target.SetString("1000000000000000000000000000000000000000000000000000000000000000")
	compar.SetString("1000000000000000000000000000000000000000000000000000000000000001")
	if target.IsMetBy(compar) {
		t.Error("should have failed to meet target")
	}

	/// meets (shared nonzero prefix, hash < target)
	compar.SetString("1000000000000000000000000000000000000000000000000000000000000000")
	if !target.IsMetBy(compar) {
		t.Error("should have met target")
	}

	/// meets
	/// TODO: add .Div
	// target.SetString("00000000000000000000000000000000000000000000000000c0f93f06000000")
	// t.Log(target)
	// comp.SetString("")
	// if !target.IsMetBy(comp) {
	// 	t.Error("should have met target")
	// }

	/// ensure .String doesnt mutate
	if target.String() != target.String() {
		t.Fatal("U256.String() mutates when it shouldnt")
	}
}

func TestU256LittleEndian(t *testing.T) {
	const display = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	u := stratumv2.U256{}
	if err := u.SetString(display); err != nil {
		t.Fatal(err)
	}
	if u[0] != 0x1f {
		t.Fatalf("first byte = %#02x, want least-significant byte 0x1f", u[0])
	}
	if got := u.String(); got != display {
		t.Fatalf("String() = %q, want %q", got, display)
	}
	const raw = "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"
	if got := u.StringNonReversed(); got != raw {
		t.Fatalf("StringNonReversed() = %q, want %q", got, raw)
	}

	roundTrip := stratumv2.U256{}
	if err := roundTrip.SetBytes(u.CloneBytes()); err != nil {
		t.Fatal(err)
	}
	if got := roundTrip.String(); got != display {
		t.Fatalf("SetBytes round trip = %q, want %q", got, display)
	}
}

func TestU256Add(t *testing.T) {
	target := stratumv2.U256{}
	comp := stratumv2.U256{}
	expected := stratumv2.U256{}
	/// math
	target.SetString("00000000000000000000000000000000000000000000000000000000000000ff")
	comp.SetString("00000000000000000000000000000000000000000000000000000000000000ef")
	expected.SetString("00000000000000000000000000000000000000000000000000000000000001ee")
	res := target.Add(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 addition failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}
	target.SetString("000000000000000000000000000000000000000000000000000000000000ffff")
	comp.SetString("000000000000000000000000000000000000000000000000000000000000ffff")
	expected.SetString("000000000000000000000000000000000000000000000000000000000001fffe")
	res = target.Add(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 addition failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}

	target.SetString("000000000000000000000000000000000000000000000000000000000007b24b")
	comp.SetString("00000000000000000000000000000000000000000000000000000000001e4958")
	expected.SetString("000000000000000000000000000000000000000000000000000000000025fba3")

	res = target.Add(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 addition failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}
	if diff, err := strconv.ParseInt(res.String(), 16, 64); diff != 0x25fba3 {
		if err != nil {
			t.Fatal(err)
		}
		t.Fatalf("diff sum not 2489251, got %d", diff)
	}

	target.SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	comp.SetString("000000000000000000000000000000000000000000000000000000000000ffff")
	expected.SetString("000000000000000000000000000000000000000000000000000000000000fffe")

	res = target.Add(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 addition failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}
}
func TestU256Sub(t *testing.T) {
	target := stratumv2.U256{}
	comp := stratumv2.U256{}
	expected := stratumv2.U256{}
	/// math
	target.SetString("00000000000000000000000000000000000000000000000000000000000000ff")
	comp.SetString("00000000000000000000000000000000000000000000000000000000000000ef")
	expected.SetString("0000000000000000000000000000000000000000000000000000000000000010")
	res := target.Sub(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 subtraction failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}

	target.SetString("00000000000000000000000000000000000000000000000000000000deadbeef")
	comp.SetString("00000000000000000000000000000000000000000000000000000000beefdead")
	expected.SetString("000000000000000000000000000000000000000000000000000000001fbde042")
	res = target.Sub(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 subtraction failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}

	/// overflow
	target.SetString("0000000000000000000000000000000000000000000000000000000000000000")
	comp.SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	expected.SetString("0000000000000000000000000000000000000000000000000000000000000001")
	res = target.Sub(comp)
	if !expected.IsEqual(res) {
		t.Fatalf("U256 subtraction failure:\ngot:\n\t%x\nwanted:\n\t%x", res[:], expected[:])
	}
}

func TestU256MulDiv(t *testing.T) {
	rnd := rand.New(rand.NewSource(0x420))
	modulus := new(big.Int).Lsh(big.NewInt(1), 256)

	pairs := [][2]string{
		/// zeroes and ones
		{"0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000001"},
		{"0000000000000000000000000000000000000000000000000000000000000001", "0000000000000000000000000000000000000000000000000000000000000001"},
		/// max values
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
		{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0000000000000000000000000000000000000000000000000000000000000002"},
		/// powers of two
		{"8000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000002"},
		{"0000000000000000000000000000000100000000000000000000000000000000", "0000000000000000000000000000000100000000000000000000000000000000"},
		///  0xdeadbeef * 0x00010001
		{"00000000000000000000000000000000000000000000000000000000deadbeef", "0000000000000000000000000000000000000000000000000000000000010001"},
	}
	/// random values
	for range 512 {
		a := &stratumv2.U256{}
		b := &stratumv2.U256{}
		rnd.Read(a[:])
		rnd.Read(b[:])
		pairs = append(pairs, [2]string{a.String(), b.String()})
	}

	for _, pair := range pairs {
		a := &stratumv2.U256{}
		b := &stratumv2.U256{}
		if err := a.SetString(pair[0]); err != nil {
			t.Fatal(err)
		}
		if err := b.SetString(pair[1]); err != nil {
			t.Fatal(err)
		}
		aBig := u256ToBig(a)
		bBig := u256ToBig(b)

		/// mul
		want := new(big.Int).Mod(new(big.Int).Mul(aBig, bBig), modulus)
		if got := a.Mul(*b); !got.IsEqual(*bigToU256(want)) {
			t.Fatalf("U256 mul failure:\n%s *\n%s =\ngot\n\t%s\nwanted\n\t%s",
				a.String(), b.String(),
				got.String(), bigToU256(want).String())
		}

		/// div
		if bBig.Sign() != 0 {
			want := new(big.Int).Quo(aBig, bBig)
			if got := a.Div(*b); !got.IsEqual(*bigToU256(want)) {
				t.Fatalf("U256 div failure:\n%s /\n%s =\ngot\n\t%s\nwanted\n\t%s",
					a.StringNonReversed(), b.StringNonReversed(),
					got.StringNonReversed(), bigToU256(want).StringNonReversed())
			}
		}
	}
}

func TestU256DivByZero(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on division by zero")
		}
	}()
	one := &stratumv2.U256{}
	one[0] = 1
	one.Div(stratumv2.U256{})
}

// bench set and compare
func BenchmarkU256SetString(b *testing.B) {
	b1 := hexDec("00ff000000000000000000000000000000000000000000000000000000000000")

	u1 := &stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := stratumv2.U256{}
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

	u1 := stratumv2.U256{}
	u1.SetBytes(b1)
	for b.Loop() {
		u2 := stratumv2.U256{}
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

func u256ToBig(u *stratumv2.U256) *big.Int {
	be := make([]byte, 32)
	for i := range 32 {
		be[i] = u[31-i]
	}
	return new(big.Int).SetBytes(be)
}

func bigToU256(b *big.Int) *stratumv2.U256 {
	be := b.FillBytes(make([]byte, 32))
	u := &stratumv2.U256{}
	for i := range 32 {
		u[i] = be[31-i]
	}
	return u
}
