package stratumv2_test

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"git.0xf0xx0.eth.limo/0xf0xx0/stratumv2"
)

var _ net.Conn = (*stratumv2.ClientConn)(nil)

type clientConnTestServer struct {
	conn net.Conn
	/// read decrypts client messages; write encrypts server messages.
	read  *stratumv2.CipherState
	write *stratumv2.CipherState
}

type clientConnHandshakeResult struct {
	read  *stratumv2.CipherState
	write *stratumv2.CipherState
	err   error
}

// Rejects reads and writes before the handshake.
func TestClientConnHandshakeRequired(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	conn := stratumv2.NewSv2Conn(clientRaw)
	if n, err := conn.Write([]byte("plaintext")); err == nil || n != 0 {
		t.Fatalf("Write before handshake = (%d, %v), want (0, error)", n, err)
	}
	if n, err := conn.Read(make([]byte, 1)); err == nil || n != 0 {
		t.Fatalf("Read before handshake = (%d, %v), want (0, error)", n, err)
	}
}

// Exchanges encrypted frames in both directions.
func TestClientConnFrameRoundTrip(t *testing.T) {
	client, server := newClientConnTestPair(t)

	params := &stratumv2.SetupConnection{
		Protocol:              stratumv2.MiningProtocol,
		MinVersion:            stratumv2.ProtocolVersion,
		MaxVersion:            stratumv2.ProtocolVersion,
		Flags:                 stratumv2.RequiresStandardJobsFlag,
		EndpointPort:          1222,
		EndpointHost:          "hosty",
		DeviceVendor:          "0xf0xx0",
		DeviceHardwareVersion: "maybe",
		DeviceFirmware:        "go-sv2-test",
		DeviceID:              "bluuchuu",
	}
	frame, err := stratumv2.NewFrame(stratumv2.MessageSetupConnection, stratumv2.ExtensionTypeCore, params)
	if err != nil {
		t.Fatal(err)
	}

	type writeResult struct {
		n   int
		err error
	}
	clientResult := make(chan writeResult, 1)
	go func() {
		n, err := client.WriteFrame(frame)
		clientResult <- writeResult{n: n, err: err}
	}()
	fromClient, clientReadErr := server.read.DecryptFrameFromReader(server.conn)
	clientWriteResult := <-clientResult
	if clientWriteResult.err != nil {
		t.Fatalf("WriteFrame failed: %v", clientWriteResult.err)
	}
	if clientWriteResult.n == 0 {
		t.Fatal("WriteFrame wrote no bytes")
	}
	if clientReadErr != nil {
		t.Fatalf("server failed to decrypt client frame: %v", clientReadErr)
	}
	assertClientConnFrameEqual(t, fromClient, frame)

	serverResult := make(chan writeResult, 1)
	go func() {
		n, err := server.write.EncryptFrameToWriter(frame, server.conn)
		serverResult <- writeResult{n: n, err: err}
	}()
	fromServer, serverReadErr := client.ReadFrame()
	serverWriteResult := <-serverResult
	if serverWriteResult.err != nil {
		t.Fatalf("server frame write failed: %v", serverWriteResult.err)
	}
	if serverWriteResult.n == 0 {
		t.Fatal("server wrote no frame bytes")
	}
	if serverReadErr != nil {
		t.Fatalf("ReadFrame failed: %v", serverReadErr)
	}
	assertClientConnFrameEqual(t, fromServer, frame)
}

// Encrypts writes and decrypts reads.
func TestClientConnReadWrite(t *testing.T) {
	client, server := newClientConnTestPair(t)
	payload := []byte("/pogolo/")

	type writeResult struct {
		n   int
		err error
	}
	clientResult := make(chan writeResult, 1)
	go func() {
		n, err := client.Write(payload)
		clientResult <- writeResult{n: n, err: err}
	}()

	ciphertext := make([]byte, len(payload)+stratumv2.MacLen)
	if _, err := io.ReadFull(server.conn, ciphertext); err != nil {
		t.Fatalf("failed to read client ciphertext: %v", err)
	}
	clientWriteResult := <-clientResult
	if clientWriteResult.err != nil {
		t.Fatalf("Write failed: %v", clientWriteResult.err)
	}
	if clientWriteResult.n == 0 {
		t.Fatal("Write wrote no bytes")
	}
	decrypted, err := server.read.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("server failed to decrypt client write: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("server decrypted %q, want %q", decrypted, payload)
	}

	ciphertext, err = server.write.Encrypt(payload)
	if err != nil {
		t.Fatalf("server encryption failed: %v", err)
	}
	serverResult := make(chan writeResult, 1)
	go func() {
		n, err := server.conn.Write(ciphertext)
		serverResult <- writeResult{n: n, err: err}
	}()

	buf := make([]byte, len(ciphertext))
	n, clientReadErr := client.Read(buf)
	serverWriteResult := <-serverResult
	if serverWriteResult.err != nil {
		t.Fatalf("server write failed: %v", serverWriteResult.err)
	}
	if clientReadErr != nil {
		t.Fatalf("Read failed: %v", clientReadErr)
	}
	if n == 0 {
		t.Fatal("Read returned no bytes")
	}
	if !bytes.Equal(buf[:len(payload)], payload) {
		t.Fatalf("Read decrypted %q, want %q", buf[:len(payload)], payload)
	}
}

// Delegates net.Conn methods to the underlying connection.
func TestClientConnNetConnDelegation(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()
	conn := stratumv2.NewSv2Conn(clientRaw)

	if conn.LocalAddr() != clientRaw.LocalAddr() {
		t.Error("LocalAddr does not delegate to the underlying connection")
	}
	if conn.RemoteAddr() != clientRaw.RemoteAddr() {
		t.Error("RemoteAddr does not delegate to the underlying connection")
	}

	deadline := time.Now().Add(time.Second)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline failed: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline failed: %v", err)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline failed: %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	if _, err := clientRaw.Write([]byte{0}); err == nil {
		t.Fatal("underlying connection is still writable after Close")
	}
}

func newClientConnTestPair(t *testing.T) (*stratumv2.ClientConn, clientConnTestServer) {
	t.Helper()

	clientRaw, serverRaw := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverRaw.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	authority := stratumv2.NewKeypair()
	static := stratumv2.NewKeypair()
	cert, err := stratumv2.NewSignedCertificate(authority.Private, static.PublicKey(), 0, uint32(time.Now().Unix())+3600)
	if err != nil {
		t.Fatal(err)
	}

	client := stratumv2.NewSv2Conn(clientRaw)
	resultCh := make(chan clientConnHandshakeResult, 1)
	go func() {
		serverHandshake := &stratumv2.HandshakeState{}
		read, write, err := serverHandshake.PerformHandshakeResponder(serverRaw, cert, static)
		resultCh <- clientConnHandshakeResult{read: read, write: write, err: err}
	}()

	clientErr := client.PerformHandshake()
	result := <-resultCh
	if clientErr != nil {
		t.Fatalf("client handshake failed: %v", clientErr)
	}
	if result.err != nil {
		t.Fatalf("server handshake failed: %v", result.err)
	}

	server := clientConnTestServer{conn: serverRaw, read: result.read, write: result.write}
	t.Cleanup(func() {
		client.Close()
		serverRaw.Close()
	})
	return client, server
}

func assertClientConnFrameEqual(t *testing.T, got, want *stratumv2.Frame) {
	t.Helper()
	if got == nil {
		t.Fatal("decoded frame is nil")
	}
	if got.MessageType != want.MessageType {
		t.Errorf("message type = %v, want %v", got.MessageType, want.MessageType)
	}
	if got.ExtensionType != want.ExtensionType {
		t.Errorf("extension type = %#x, want %#x", got.ExtensionType, want.ExtensionType)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("payload mismatch:\ngot  %x\nwant %x", got.Payload, want.Payload)
	}
}
