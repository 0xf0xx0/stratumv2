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
	poolhost = "[::1]"
	poolport = 5661
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
		Protocol:              stratumv2.MiningProtocol,
		MinVersion:            2,
		MaxVersion:            2,
		Flags:                 stratumv2.RequiresExtendedChannelsFlag,
		EndpointPort:          uint16(poolport),
		EndpointHost:          poolhost,
		DeviceVendor:          "Hashfox",
		DeviceHardwareVersion: "Hex",
		DeviceFirmware:        "esp-miner-v69.420-evil-closed-source-fork",
		DeviceID:              "bluuchuu",
	}
	openchanmsg := stratumv2.OpenExtendedMiningChannel{
		OpenStandardMiningChannel: stratumv2.OpenStandardMiningChannel{
			RequestID:       newReqID(),
			UserIdentity:    addr.EncodeAddress(),
			NominalHashRate: 1e12,
			MaxTarget:       maxtarget,
		},
		MinExtranonceSize: 4,
	}
	setupPayload, err := setupmsg.Encode()
	if err != nil {
		panic(err)
	}
	setupFrame := stratumv2.Frame{
		MessageType:   stratumv2.MessageSetupConnection,
		MessageLength: stratumv2.U24(len(setupPayload)),
		Payload:       setupPayload,
	}
	setupBytes, err := setupFrame.Encode()
	if err != nil {
		panic(err)
	}
	openchanPayload, err := openchanmsg.Encode()
	if err != nil {
		panic(err)
	}
	openchanFrame := stratumv2.Frame{
		MessageType:   stratumv2.MessageOpenExtendedMiningChannel,
		MessageLength: stratumv2.U24(len(openchanPayload)),
		Payload:       openchanPayload,
	}
	openchanBytes, err := openchanFrame.Encode()
	if err != nil {
		panic(err)
	}

	conn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(poolhost+":"+strconv.Itoa(poolport))))
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			frame := stratumv2.Frame{}
			err := frame.DecodeFromReader(conn)
			if err != nil {
				panic(err)
			}
			bytes, _ := frame.Encode()
			fmt.Printf("RX: %x\n", bytes)
		}
	}()

	fmt.Printf("TX: %x\n", setupBytes)
	conn.Write(setupBytes)
	fmt.Printf("TX: %x\n", openchanBytes)
	conn.Write(openchanBytes)
	<-sigs
	conn.Close()
}
func newReqID() uint32 {
	reqid++
	return reqid
}
