package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

var (
	poolhost = "91.98.76.244" ///warppool
	poolport = 3336
	authkey  = "9ankJhx4JpKeJd7xHzPVM98kU1WppT45Pbp3LfeKVdyt5bYgBY8"
	reqid    = uint32(0)
	addr     = func() *address.AddressTaproot {
		b, _ := hex.DecodeString("8033d13ee81500afe03a9f48ed142b15724816dd9247c9cf55ae447a5b867449")
		addr, _ := address.NewAddressTaproot(b, &chaincfg.MainNetParams)
		return addr
	}()
	maxtarget = func() stratumv2.U256 {
		s := stratumv2.U256{}
		s.SetString("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
		return s
	}()
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	setupmsg := stratumv2.SetupConnection{
		Protocol:     stratumv2.MiningProtocol,
		MinVersion:   stratumv2.ProtocolVersion,
		MaxVersion:   stratumv2.ProtocolVersion,
		Flags:        stratumv2.RequiresExtendedChannelsFlag,
		EndpointPort: uint16(poolport),
		EndpointHost: poolhost,
		DeviceVendor: "0xf0xx0",
		// DeviceHardwareVersion: "maybe",
		// DeviceFirmware:        "go-sv2-test",
		// DeviceID:              "bluuchuu",
	}
	// openchanmsg := stratumv2.OpenExtendedMiningChannel{
	// 	OpenStandardMiningChannel: stratumv2.OpenStandardMiningChannel{
	// 		RequestID:       newReqID(),
	// 		UserIdentity:    addr.EncodeAddress(),
	// 		NominalHashRate: 1e12,
	// 		MaxTarget:       maxtarget,
	// 	},
	// 	MinExtranonceSize: 1,
	// }
	setupPayload, err := setupmsg.Encode()
	if err != nil {
		panic(err)
	}
	setupFrame := stratumv2.Frame{
		MessageType:   stratumv2.MessageSetupConnection,
		MessageLength: stratumv2.U24(len(setupPayload)),
		Payload:       setupPayload,
	}
	// openchanPayload, err := openchanmsg.Encode()
	// if err != nil {
	// 	panic(err)
	// }
	// openchanFrame := stratumv2.Frame{
	// 	MessageType:   stratumv2.MessageOpenExtendedMiningChannel,
	// 	MessageLength: stratumv2.U24(len(openchanPayload)),
	// 	Payload:       openchanPayload,
	// }
	// _ = openchanFrame

	cliPaw := &stratumv2.HandshakeState{}
	authorityPubkey, err := stratumv2.DeserializeAuthorityKey(authkey)
	if err != nil {
	panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(poolhost+":"+strconv.Itoa(poolport))))
	if err != nil {
		panic(err)
	}

	send, recv, err := cliPaw.PerformHandshakeInitiator(conn, [32]byte(authorityPubkey))
	if err != nil {
		panic(err)
	}
	_ = recv
	_ = send

	// conn.Write([]byte("random bullshit go"))
	setupBytes, err := send.EncryptFrame(setupFrame)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("%+v\n", setupmsg)
	// fmt.Printf("%+v\n", setupFrame)
	fmt.Printf("TX: %x\n", setupBytes)
	/*go func() {
		b, err := io.ReadAll(conn)
		if err != nil {
			panic(err)
		}
		fmt.Printf("RX: %x", b)
	}()*/
	conn.Write(setupBytes)
	go func() {
	 	for {
 		frame, err := recv.DecryptFrame(conn)
		if err != nil {
	 			panic(err)
	 		}
	 		bytes, _ := frame.Encode()
	 		fmt.Printf("RX: %x\n", bytes)
	 	}
	}()

	// openchanBytes, err := send.EncryptFrame(openchanFrame)
	// if err != nil {
	// panic(err)
	// }
	// fmt.Printf("TX: %x\n", openchanBytes)
	// conn.Write(openchanBytes)

	<-sigs
	conn.Close()
}
func newReqID() uint32 {
	reqid++
	return reqid
}
