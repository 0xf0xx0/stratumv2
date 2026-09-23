// test client
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
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
)
var (
	reqid  = uint32(0)
	chanid = -1
)

func main() {
	log.SetFlags(log.Lmicroseconds | log.LUTC)
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	opts := flag.NewFlagSet("sv2-logger", flag.ExitOnError)

	srv := opts.String("server", "127.0.0.1", "server ip to connect to")
	port := opts.Uint("port", 5661, "server port")
	auth := opts.String("authority", "", "authority key to validate against (empty = no validation)")
	chainAddr := opts.String("address", "", "on-chain address to authorize as (default: hardcoded bytes idk)")

	if opts.Parse(os.Args[1:]) != nil {
		return
	}
	if srv != nil {
		poolhost = *srv
	}
	if port != nil {
		poolport = uint16(*port)
	}
	if auth != nil {
		authkey = *auth
	}
	if chainAddr != nil && *chainAddr != "" {
		addr, _ = address.DecodeAddress(*chainAddr, &chaincfg.MainNetParams)
	}

	setupmsg := stratumv2.SetupConnection{
		Protocol:              stratumv2.MiningProtocol,
		MinVersion:            stratumv2.ProtocolVersion,
		MaxVersion:            stratumv2.ProtocolVersion,
		Flags:                 stratumv2.RequiresExtendedChannelsFlag,
		EndpointPort:          poolport,
		EndpointHost:          poolhost,
		DeviceVendor:          "0xf0xx0",
		DeviceHardwareVersion: "logger.go",
		DeviceFirmware:        "git.0xf0xx0.eth.limo/0xf0xx0/stratumv2",
		DeviceID:              "paws",
	}
	openchanmsg := stratumv2.OpenExtendedMiningChannel{
		OpenStandardMiningChannel: stratumv2.OpenStandardMiningChannel{
			RequestID:       newReqID(),
			UserIdentity:    addr.EncodeAddress() + ".sv2-logger",
			NominalHashRate: 1e12,
			MaxTarget:       maxtarget,
		},
		MinExtranonceSize: 1,
	}
	setupPayload, _ := setupmsg.Encode()
	openchanPayload, _ := openchanmsg.Encode()
	setupFrame := stratumv2.Frame{
		MessageType:   stratumv2.MessageSetupConnection,
		MessageLength: stratumv2.U24(len(setupPayload)),
		Payload:       setupPayload,
	}
	openchanFrame := stratumv2.Frame{
		MessageType:   stratumv2.MessageOpenExtendedMiningChannel,
		MessageLength: stratumv2.U24(len(openchanPayload)),
		Payload:       openchanPayload,
	}

	/// connect
	clientPaw := &stratumv2.HandshakeState{}

	rawConn, err := net.DialTCP("tcp", nil, net.TCPAddrFromAddrPort(netip.MustParseAddrPort(poolhost+":"+strconv.Itoa(int(poolport)))))
	if err != nil {
		log.Fatal(err.Error())
	}

	send, recv, err := clientPaw.PerformHandshakeInitiator(rawConn)
	if err != nil {
		log.Fatal(err.Error())
	}
	conn := &Sv2Conn{
		netConn: rawConn,
		send:    send,
		recv:    recv,
	}

	if authkey != "" {
		authorityPubkey, err := stratumv2.DeserializeAuthorityKey(authkey)
		if err != nil {
			log.Fatal(err.Error())
		}
		valid, err := clientPaw.VerifyServerCertificate(stratumv2.Pubkey(authorityPubkey))
		if err != nil {
			log.Fatal(err.Error())
		}
		if !valid {
			log.Fatal("cert validation failed!")
		}
		println("cert validation success!")
	}

	go func() {
		for {
			frame, err := conn.ReadFrame()
			if err != nil {
				if err == io.EOF || errors.Is(err, net.ErrClosed) {
					return
				}
				log.Fatal(err.Error())
			}

			if frame.MessageType == stratumv2.MessageOpenExtendedMiningChannelSuccess {
				msg := stratumv2.OpenExtendedMiningChannelSuccess{}
				msg.Decode(frame.Payload)
				chanid = int(msg.ChannelID)
			}
		}
	}()

	_, err = conn.WriteFrame(setupFrame)
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = conn.WriteFrame(openchanFrame)
	if err != nil {
		log.Fatal(err.Error())
	}

	<-sigs
	if chanid > -1 {
		closemsg := stratumv2.CloseChannel{
			ChannelID:  uint32(chanid),
			ReasonCode: "ubisoft go steamworks bye bye, always on drm",
		}
		closemsgPayload, err := closemsg.Encode()
		if err != nil {
			log.Fatal(err.Error())
		}
		closemsgFrame := stratumv2.Frame{
			MessageType:   stratumv2.MessageCloseChannel,
			MessageLength: stratumv2.U24(len(closemsgPayload)),
			Payload:       closemsgPayload,
		}
		_, err = conn.WriteFrame(closemsgFrame)
		if err != nil {
			log.Println(err.Error())
		}
	}

	// closemsgBytes, err := send.EncryptFrame(closemsgFrame)
	//
	// conn.Write(closemsgBytes)
	conn.Close()
}
func newReqID() uint32 {
	reqid++
	return reqid
}

// wrapper to enc/dec and log frames
type Sv2Conn struct {
	netConn    net.Conn
	send, recv *stratumv2.CipherState
}

func (conn *Sv2Conn) WriteFrame(frame stratumv2.Frame) (int, error) {
	plainBytes, _ := frame.Encode()
	log.Printf("TX: (%s) %x\n", frame.MessageType, plainBytes)
	return conn.send.EncryptFrameToWriter(frame, conn.netConn)
}
func (conn *Sv2Conn) ReadFrame() (stratumv2.Frame, error) {
	frame, err := conn.recv.DecryptFrameFromReader(conn.netConn)
	if err == nil {
		plainBytes, _ := frame.Encode()
		log.Printf("RX: (%s) %x\n", frame.MessageType, plainBytes)
	}
	return frame, err
}

/// net.Conn impl

func (conn *Sv2Conn) Write(b []byte) (int, error) {
	return conn.netConn.Write(b)
}
func (conn *Sv2Conn) Read(b []byte) (int, error) {
	return conn.netConn.Read(b)
}
func (conn *Sv2Conn) Close() error {
	return conn.netConn.Close()
}
func (conn *Sv2Conn) LocalAddr() net.Addr {
	return conn.netConn.LocalAddr()
}
func (conn *Sv2Conn) RemoteAddr() net.Addr {
	return conn.netConn.RemoteAddr()
}
func (conn *Sv2Conn) SetDeadline(t time.Time) error {
	return conn.netConn.SetDeadline(t)
}
func (conn *Sv2Conn) SetReadDeadline(t time.Time) error {
	return conn.netConn.SetReadDeadline(t)
}
func (conn *Sv2Conn) SetWriteDeadline(t time.Time) error {
	return conn.netConn.SetWriteDeadline(t)
}
