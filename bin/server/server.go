// test client
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2/bin/shared"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
)

var (
	poolhost = "91.98.76.244" ///warppool
	poolport = uint16(3336)
	authkey  = "9ankJhx4JpKeJd7xHzPVM98kU1WppT45Pbp3LfeKVdyt5bYgBY8"
	addr     = func() address.Address {
		b, _ := hex.DecodeString("8033d13ee81500afe03a9f48ed142b15724816dd9247c9cf55ae447a5b867449")
		addr, _ := address.NewAddressTaproot(b, &chaincfg.MainNetParams)
		return addr
	}()
	maxtarget = func() stratumv2.U256 {
		s := stratumv2.U256{}
		s.SetString("00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
		return s
	}()
	loog = shared.Logger
)
var (
	reqid  = uint32(0)
	chanid = -1
)

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	opts := flag.NewFlagSet("sv2-logger", flag.ExitOnError)

	srv := opts.String("server", "127.0.0.1", "server ip to connect to")
	port := opts.Uint("port", 5661, "server port")
	if opts.Parse(os.Args[1:]) != nil {
		return
	}
	if srv != nil {
		poolhost = *srv
	}
	if port != nil {
		poolport = uint16(*port)
	}

	/// connect
	clientPaw := &stratumv2.HandshakeState{}
	authKey := stratumv2.NewKeypair()
	staticKey := stratumv2.NewKeypair()
	cert, _ := stratumv2.NewSignedCertificate(authKey.Private, staticKey.PublicKey(), 0, 65535)

	listener, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.MustParseAddrPort(poolhost+":"+strconv.Itoa(int(poolport)))))
	if err != nil {
		loog.Fatal(err.Error())
	}
	println(fmt.Sprintf("listening on %s:%d", poolhost, poolport))

	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				println(fmt.Sprintf("accept error: %s", err.Error()))
				continue
			}
			println(fmt.Sprintf("new conn: %s", rawConn.RemoteAddr().String()))
			go func() {
				recv, send, err := clientPaw.PerformHandshakeResponder(rawConn, cert, staticKey)
				if err != nil {
					loog.Fatal(err.Error())
				}
				conn := &shared.Sv2Conn{
					NetConn: rawConn,
					Send:    send,
					Recv:    recv,
				}

				frame, err := conn.ReadFrame()
				if err != nil {
					if err == io.EOF || errors.Is(err, net.ErrClosed) {
						return
					}
					loog.Fatal(err.Error())
				}
				if frame.MessageType != stratumv2.MessageSetupConnection {
					return
				}
				sendFrame := &stratumv2.Frame{}
				sendFrame.FromParams(stratumv2.MessageSetupConnectionSuccess,
					&stratumv2.SetupConnectionSuccess{
						UsedVersion: stratumv2.ProtocolVersion,
						Flags:       0,
					},
				)
				// msg := stratumv2.SetupConnection{}
				// frame.ToParams(&msg)

				for {
					_, err := conn.ReadFrame()
					if err != nil {
						if err == io.EOF || errors.Is(err, net.ErrClosed) {
							return
						}
						loog.Fatal(err.Error())
					}
				}
			}()
		}
	}()

	<-sigs
}
func newReqID() uint32 {
	reqid++
	return reqid
}
