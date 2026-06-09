package stratumv2_test

import (
	"testing"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

func TestExtendedJobDecode(t *testing.T) {

	b := hexDec("2d00000059b92e0101dbf4256a00000020010c9d0df206ca787f5ef6a0673c59e1e6e6b0d04629b434e16fa0eb92d2434f23b9ac14e5f8b7f44506f9704f616b2f05fc1b0ea9e3c15c1780d77201b1c8624534cf69581a6ff276567c9cbff22fbccb699146410e99818e803ab62c7b81cd6358909c411002b8f6c9ce2a9765b07e8d23a74ebd58fb554d8ec7e51bab6189602026603cb2ce317677277449ff0ff2f8c901435019212f79be91ae0565a5fd0d699eb03556eea52f878c81542f8ca4836c6777226bdbf34401b3e1166d107fc7aefac91ecae611b1ae9945ebadf14befded136a8938a433d827154d34ede204e7d4875406246821a7d9ba9464ed414477f37189eb7bea2953f38cbe59111659b742c409b1a5a5b79441241d368770f2dc28d1838d9bdc9d702a683c6cf6221ce214dfc9afb949ff75cbf64e845a324d0f18a128c82bf9719a7efaf62109a78a1569b55687630daa12a730fa34a67f5b0fbab1f8abfe47dba212bcebc3912976a0fbae218ebc56bb4cd38fd3b71c346bb5495c8ea956593e3bbb1fbc7adb051aefa390002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff1903c4890e5075626c69632d506f6f6c6300ffffffff025444c312000000002251207ad80adf83bc1d7de821b64903694ce5e71d55cefaa2692812f75ee6ba182abf0000000000000000266a24aa21a9ed6543d3755dfba0787f50c57aa1988fd1f934381b80af24dd312169c29701eb8600000000")

	m := stratumv2.NewExtendedMiningJob{}

	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestExtendedSubmitDecode(t *testing.T) {
	b := hexDec("00801b1f00002d000000060000001f1e2f01a18a144c53f5256a00e00a200600000000000a")
	f := stratumv2.Frame{}
	m := stratumv2.SubmitSharesExtended{}
	if err := f.Decode(b); err != nil {
		t.Logf("%+v", f)
		t.Fatal(err.Error())
	}
	if err := m.Decode(f.Payload); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestSubmitAccept(t *testing.T) {

	b := hexDec("2d0000000000000001000000491b000000000000")

	m := stratumv2.SubmitSharesSuccess{}

	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestSetTarget(t *testing.T) {

	b := hexDec("2d000000000000000000000000000000000000000000000000000000f8ff070000000000")

	m := stratumv2.SetTarget{}

	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}

func TestSetNewPrevHash(t *testing.T) {

	b := hexDec("2d0000006b202f01c46b633188fbe8a156e2c1fdb6fa92888efce6e618960000000000000000000061f5256a8f060217")

	m := stratumv2.SetNewPrevHash{}

	if err := m.Decode(b); err != nil {
		t.Logf("%+v", m)
		t.Fatal(err.Error())
	}
	t.Logf("%+v", m)
}
