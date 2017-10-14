package smtpd

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Create test server to run commands against.
// Sleep to give ListenAndServe time to finishing listening before creating clients.
// This seems to only be necessary since Go 1.5.
// For specific TLS tests, a different server is created with a net.Pipe connection inside each individual test, in order to change the server settings for each test.
func init() {
	server := &Server{Addr: "127.0.0.1:52525", Handler: nil}
	go server.ListenAndServe()
	time.Sleep(1 * time.Millisecond)
}

// Create a client to run commands with. Parse the banner for 220 response.
func newConn(t *testing.T) net.Conn {
	conn, err := net.Dial("tcp", "127.0.0.1:52525")
	if err != nil {
		t.Fatalf("Failed to connect to test server: %v", err)
	}
	banner, readErr := bufio.NewReader(conn).ReadString('\n')
	if readErr != nil {
		t.Fatalf("Failed to read banner from test server: %v", readErr)
	}
	if banner[0:3] != "220" {
		t.Fatalf("Read incorrect banner from test server: %v", banner)
	}
	return conn
}

// Send a command and verify the 3 digit code from the response.
func cmdCode(t *testing.T, conn net.Conn, cmd string, code string) {
	fmt.Fprintf(conn, "%s\r\n", cmd)
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("Failed to read response from test server: %v", err)
	}
	if resp[0:3] != code {
		t.Errorf("Command \"%s\" response code is %s, want %s", cmd, resp[0:3], code)
	}
}

// Simple tests: connect, send command, then send QUIT.
// RFC 2821 section 4.1.4 specifies that these commands do not require a prior EHLO,
// only that clients should send one, so test without EHLO.
func TestSimpleCommands(t *testing.T) {
	tests := []struct {
		cmd  string
		code string
	}{
		{"NOOP", "250"},
		{"RSET", "250"},
		{"HELP", "502"},
		{"VRFY", "502"},
		{"EXPN", "502"},
		{"TEST", "500"}, // Unsupported command
		{"", "500"},     // Blank command
	}

	for _, tt := range tests {
		conn := newConn(t)
		cmdCode(t, conn, tt.cmd, tt.code)
		cmdCode(t, conn, "QUIT", "221")
		conn.Close()
	}
}

func TestCmdHELO(t *testing.T) {
	conn := newConn(t)

	// Send HELO, expect greeting.
	cmdCode(t, conn, "HELO host.example.com", "250")

	// Verify that HELO resets the current transaction state like RSET.
	// RFC 2821 section 4.1.4 says EHLO should cause a reset, so verify that HELO does it too.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "HELO host.example.com", "250")
	cmdCode(t, conn, "DATA", "503")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdEHLO(t *testing.T) {
	conn := newConn(t)

	// Send EHLO, expect greeting.
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// Verify that EHLO resets the current transaction state like RSET.
	// See RFC 2821 section 4.1.4 for more detail.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "EHLO host.example.com", "250")
	cmdCode(t, conn, "DATA", "503")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdRSET(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// Verify that RSET clears the current transaction state.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "RSET", "250")
	cmdCode(t, conn, "DATA", "503")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdMAIL(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// MAIL with no FROM arg should return 501 syntax error
	cmdCode(t, conn, "MAIL", "501")
	// MAIL with empty FROM arg should return 501 syntax error
	cmdCode(t, conn, "MAIL FROM:", "501")
	// MAIL with DSN-style FROM arg should return 250 Ok
	cmdCode(t, conn, "MAIL FROM:<>", "250")
	// MAIL with valid FROM arg should return 250 Ok
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdRCPT(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// RCPT without prior MAIL should return 503 bad sequence
	cmdCode(t, conn, "RCPT", "503")

	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")

	// RCPT with no TO arg should return 501 syntax error
	cmdCode(t, conn, "RCPT", "501")

	// RCPT with empty TO arg should return 501 syntax error
	cmdCode(t, conn, "RCPT TO:", "501")

	// RCPT with valid TO arg should return 250 Ok
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")

	// Up to 100 valid recipients should return 250 Ok
	for i := 2; i < 101; i++ {
		cmdCode(t, conn, fmt.Sprintf("RCPT TO:<recipient%v@example.com>", i), "250")
	}

	// 101st valid recipient with valid TO arg should return 452 too many recipients
	cmdCode(t, conn, "RCPT TO:<recipient101@example.com>", "452")

	// RCPT with valid TO arg and prior DSN-style FROM arg should return 250 Ok
	cmdCode(t, conn, "RSET", "250")
	cmdCode(t, conn, "MAIL FROM:<>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdDATA(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// DATA without prior MAIL & RCPT should return 503 bad sequence
	cmdCode(t, conn, "DATA", "503")
	cmdCode(t, conn, "RSET", "250")

	// DATA without prior RCPT should return 503 bad sequence
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "DATA", "503")
	cmdCode(t, conn, "RSET", "250")

	// Test a full mail transaction.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "DATA", "354")
	cmdCode(t, conn, "Test message.\r\n.", "250")

	// Test a full mail transaction with a bad last recipient.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:", "501")
	cmdCode(t, conn, "DATA", "354")
	cmdCode(t, conn, "Test message.\r\n.", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdSTARTTLS(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// By default, TLS is not configured, so STARTTLS should return 502 not implemented
	cmdCode(t, conn, "STARTTLS", "502")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdSTARTTLSFailure(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Deliberately misconfigure TLS to force a handshake failure.
	server := &Server{TLSConfig: &tls.Config{}}
	session := server.newSession(serverConn)
	go session.serve()

	reader := bufio.NewReader(clientConn)
	_, _ = reader.ReadString('\n') // Read greeting message first.

	cmdCode(t, clientConn, "EHLO host.example.com", "250")

	// When TLS is configured, STARTTLS should return 220 Ready to start TLS
	cmdCode(t, clientConn, "STARTTLS", "220")

	// A failed TLS handshake should return 403 TLS handshake failed
	tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	err := tlsConn.Handshake()
	if err != nil {
		resp, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("Failed to read response after failed TLS handshake: %v", err)
		}
		if resp[0:3] != "403" {
			t.Errorf("Failed TLS handshake response code is %s, want 403", resp[0:3])
		}
	}

	cmdCode(t, clientConn, "QUIT", "221")
	tlsConn.Close()
}

// Utility function to make a valid TLS certificate for use by the server.
func makeCertificate(t *testing.T) tls.Certificate {
	const certPEM = `
-----BEGIN CERTIFICATE-----
MIID9DCCAtygAwIBAgIJAIX/1sxuqZKrMA0GCSqGSIb3DQEBCwUAMFkxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0xNzA1MDYxNDIy
MjVaFw0yNzA1MDQxNDIyMjVaMFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21l
LVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNV
BAMTCWxvY2FsaG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALO4
XVY5Kw9eNblqBenC03Wz6qemLFw8zLDNrehvjYuJPn5WVwvzLNP+3S02iqQD+Y1k
vszqDIZLQdjWLiEZdtxfemyIr+RePIMclnceGYFx3Zgg5qeyvOWlJLM41ZU8YZb/
zGj3RtXzuOZ5vePSLGS1nudjrKSBs7shRY8bYjkOqFujsSVnEK7s3Kb2Sf/rO+7N
RZ1df3hhyKtyq4Pb5eC1mtQqcRjRSZdTxva8kO4vRQbvGgjLUakvBVrrnwbww5a4
2wKbQPKIClEbSLyKQ62zR8gW1rPwBdokd8u9+rLbcmr7l0OuAsSn5Xi9x6VxXTNE
bgCa1KVoE4bpoGG+KQsCAwEAAaOBvjCBuzAdBgNVHQ4EFgQUILso/fozIhaoyi05
XNSWzP/ck+4wgYsGA1UdIwSBgzCBgIAUILso/fozIhaoyi05XNSWzP/ck+6hXaRb
MFkxCzAJBgNVBAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJ
bnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxEjAQBgNVBAMTCWxvY2FsaG9zdIIJAIX/
1sxuqZKrMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAIbzsvTZb8LA
JqyaTttsMMA1szf4WBX88lVWbIk91k0nlTa0BiU/UocKrU6c9PySwJ6FOFJpgpdH
z/kmJ+S+d4pvgqBzWbKMoMrNlMt6vL+H8Mbf/l/CN91eNM+gJZu2HgBIFGW1y4Wy
gOzjEm9bw15Hgqqs0P4CSy7jcelWA285DJ7IG1qdPGhAKxT4/UuDin8L/u2oeYWH
3DwTDO4kAUnKetcmNQFSX3Ge50uQypl8viYgFJ2axOfZ3imjQZrs7M1Og6Wnj/SD
F414wVQibsZyZp8cqwR/OinvxloPkPVnf163jPRtftuqezEY8Nyj83O5u5sC1Azs
X/Gm54QNk6w=
-----END CERTIFICATE-----`
	const keyPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAs7hdVjkrD141uWoF6cLTdbPqp6YsXDzMsM2t6G+Ni4k+flZX
C/Ms0/7dLTaKpAP5jWS+zOoMhktB2NYuIRl23F96bIiv5F48gxyWdx4ZgXHdmCDm
p7K85aUkszjVlTxhlv/MaPdG1fO45nm949IsZLWe52OspIGzuyFFjxtiOQ6oW6Ox
JWcQruzcpvZJ/+s77s1FnV1/eGHIq3Krg9vl4LWa1CpxGNFJl1PG9ryQ7i9FBu8a
CMtRqS8FWuufBvDDlrjbAptA8ogKURtIvIpDrbNHyBbWs/AF2iR3y736sttyavuX
Q64CxKfleL3HpXFdM0RuAJrUpWgThumgYb4pCwIDAQABAoIBAHzvYntJPKTvUhu2
F6w8kvHVBABNpbLtVUJniUj3G4fv/bCn5tVY1EX/e9QtgU2psbbYXUdoQRKuiHTr
15+M6zMhcKK4lsYDuL9QhU0DcKmq9WgHHzFfMK/YEN5CWT/ofNMSuhASLn0Xc+dM
pHQWrGPKWk/y25Z0z/P7mjZ0y+BrJOKlxV53A2AWpj4JtjX2YO6s/eiraFX+RNlv
GyWzeQ7Gynm2TD9VXhS+m40VVBmmbbeZYDlziDoWWNe9r26A+C8K65gZtjKdarMd
0LN89jJvI1pUxcIuvZJnumWUenZ7JhfBGpkfAwLB+MogUo9ekAHv1IZv/m3uWq9f
Zml2dZECgYEA2OCI8kkLRa3+IodqQNFrb/uZ16YouQ71B7nBgAxls9nuhyELKO7d
fzf1snPx6cbaCQKTyxrlYvck4gz8P09R7nVYwJuTmP0+QIgeCCc3Y9A2dyExaC6I
uKkFzJEqIVZNLvdjBRWQs5AiD1w58oto+wOvbagAQM483WiJ/qFaHCMCgYEA1CPo
zwI6pCn39RSYffK25HXM1q3i8ypkYdNsG6IVqS2FqHqj8XJSnDvLeIm7W1Rtw+uM
QdZ5O6PH31XgolG6LrFkW9vtfH+QnXQA2AnZQEfn034YZubhcexLqAkS9r0FUUZp
a1WI2jSxBBeB+to6MdNABuQOL3NHjPUidUKnOfkCgYA+HvKbE7ka2F+23DrfHh08
EkFat8lqWJJvCBIY73QiNAZSxnA/5UukqQ7DctqUL9U8R3S19JpH4qq55SZLrBi3
yP0HDokUhVVTfqm7hCAlgvpW3TcdtFaNLjzu/5WlvuaU0V+XkTnFdT+MTsp6YtxL
Kh8RtdF8vpZIhS0htm3tKQKBgQDQXoUp79KRtPdsrtIpw+GI/Xw50Yp9tkHrJLOn
YMlN5vzFw9CMM/KYqtLsjryMtJ0sN40IjhV+UxzbbYq7ZPMvMeaVo6vdAZ+WSH8b
tHDEBtzai5yEVntSXvrhDiimWnuCnVqmptlJG0BT+JMfRoKqtgjJu++DBARfm9hA
vTtsYQKBgE1ttTzd3HJoIhBBSvSMbyDWTED6jecKvsVypb7QeDxZCbIwCkoK9zn1
twPDHLBcUNhHJx6JWTR6BxI5DZoIA1tcKHtdO5smjLWNSKhXTsKWee2aNkZJkNIW
TDHSaTMOxVUEzpx84xClf561BTiTgzQy2MULpg3AK0Cv9l0+Yrvz
-----END RSA PRIVATE KEY-----`

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatalf("Failed to configure TLS certificate: %v", err)
	}

	return cert
}

func TestCmdSTARTTLSSuccess(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	// Configure a valid TLS certificate so the handshake will succeed.
	cert := makeCertificate(t)
	server := &Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
	session := server.newSession(serverConn)
	go session.serve()

	reader := bufio.NewReader(clientConn)
	_, _ = reader.ReadString('\n') // Read greeting message first.

	cmdCode(t, clientConn, "EHLO host.example.com", "250")

	// When TLS is configured, STARTTLS should return 220 Ready to start TLS
	cmdCode(t, clientConn, "STARTTLS", "220")

	// A successful TLS handshake shouldn't return anything, it should wait for EHLO.
	tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	err := tlsConn.Handshake()
	if err != nil {
		t.Errorf("Failed to perform TLS handshake")
	}

	// The subsequent EHLO should be successful.
	cmdCode(t, tlsConn, "EHLO host.example.com", "250")

	// When TLS is already in use, STARTTLS should return 503 bad sequence
	cmdCode(t, tlsConn, "STARTTLS", "503")

	cmdCode(t, tlsConn, "QUIT", "221")
	tlsConn.Close()
}

func TestCmdSTARTTLSRequired(t *testing.T) {
	tests := []struct {
		cmd        string
		codeBefore string
		codeAfter  string
	}{
		{"EHLO host.example.com", "250", "250"},
		{"NOOP", "250", "250"},
		{"MAIL FROM:<sender@example.com>", "530", "250"},
		{"RCPT TO:<recipient@example.com>", "530", "250"},
		{"RSET", "530", "250"}, // Reset before DATA to avoid having to actually send a message.
		{"DATA", "530", "503"},
		{"HELP", "530", "502"},
		{"VRFY", "530", "502"},
		{"EXPN", "530", "502"},
		{"TEST", "530", "500"}, // Unsupported command
		{"", "530", "500"},     // Blank command
	}

	clientConn, serverConn := net.Pipe()

	// If TLS is not configured, the TLSRequired setting is ignored, so it must be configured for this test.
	cert := makeCertificate(t)
	server := &Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}, TLSRequired: true}
	session := server.newSession(serverConn)
	go session.serve()

	reader := bufio.NewReader(clientConn)
	_, _ = reader.ReadString('\n') // Read greeting message first.

	// If TLS is required, but not in use, reject every command except NOOP, EHLO, STARTTLS, or QUIT as per RFC 3207 section 4.
	for _, tt := range tests {
		cmdCode(t, clientConn, tt.cmd, tt.codeBefore)
	}

	// Switch to using TLS.
	cmdCode(t, clientConn, "STARTTLS", "220")

	// A successful TLS handshake shouldn't return anything, it should wait for EHLO.
	tlsConn := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true})
	err := tlsConn.Handshake()
	if err != nil {
		t.Errorf("Failed to perform TLS handshake")
	}

	// The subsequent EHLO should be successful.
	cmdCode(t, tlsConn, "EHLO host.example.com", "250")

	// If TLS is required, and is in use, every command should work normally.
	for _, tt := range tests {
		cmdCode(t, tlsConn, tt.cmd, tt.codeAfter)
	}

	cmdCode(t, tlsConn, "QUIT", "221")
	tlsConn.Close()
}

func TestMakeHeaders(t *testing.T) {
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	valid := "Received: from clientName (clientHost [clientIP])\r\n" +
		"        by serverName (smtpd) with SMTP\r\n" +
		"        for <recipient@example.com>; " +
		fmt.Sprintf("%s\r\n", now)

	srv := &Server{Appname: "smtpd", Hostname: "serverName"}
	s := &session{srv: srv, remoteIP: "clientIP", remoteHost: "clientHost", remoteName: "clientName"}
	headers := s.makeHeaders([]string{"recipient@example.com"})
	if string(headers) != valid {
		t.Errorf("makeHeaders() returned\n%v, want\n%v", string(headers), valid)
	}
}

// Test parsing of commands into verbs and arguments.
func TestParseLine(t *testing.T) {
	tests := []struct {
		line string
		verb string
		args string
	}{
		{"EHLO host.example.com", "EHLO", "host.example.com"},
		{"MAIL FROM:<sender@example.com>", "MAIL", "FROM:<sender@example.com>"},
		{"RCPT TO:<recipient@example.com>", "RCPT", "TO:<recipient@example.com>"},
		{"QUIT", "QUIT", ""},
	}
	s := &session{}
	for _, tt := range tests {
		verb, args := s.parseLine(tt.line)
		if verb != tt.verb || args != tt.args {
			t.Errorf("ParseLine(%v) returned %v, %v, want %v, %v", tt.line, verb, args, tt.verb, tt.args)
		}
	}
}

// Test reading of complete lines from the socket.
func TestReadLine(t *testing.T) {
	var buf bytes.Buffer
	s := &session{}
	s.srv = &Server{}
	s.br = bufio.NewReader(&buf)

	// Ensure readLine() returns an EOF error on an empty buffer.
	_, err := s.readLine()
	if err != io.EOF {
		t.Errorf("readLine() on empty buffer returned err: %v, want EOF", err)
	}

	// Ensure trailing <CRLF> is stripped.
	line := "FOO BAR BAZ\r\n"
	cmd := "FOO BAR BAZ"
	buf.Write([]byte(line))
	output, err := s.readLine()
	if err != nil {
		t.Errorf("readLine(%v) returned err: %v", line, err)
	} else if output != cmd {
		t.Errorf("readLine(%v) returned %v, want %v", line, output, cmd)
	}
}

// Test reading of message data, including dot stuffing (see RFC 5321 section 4.5.2).
func TestReadData(t *testing.T) {
	tests := []struct {
		lines string
		data  string
	}{
		// Single line message.
		{"Test message.\r\n.\r\n", "Test message.\r\n"},

		// Single line message with leading period removed.
		{".Test message.\r\n.\r\n", "Test message.\r\n"},

		// Multiple line message.
		{"Line 1.\r\nLine 2.\r\nLine 3.\r\n.\r\n", "Line 1.\r\nLine 2.\r\nLine 3.\r\n"},

		// Multiple line message with leading period removed.
		{"Line 1.\r\n.Line 2.\r\nLine 3.\r\n.\r\n", "Line 1.\r\nLine 2.\r\nLine 3.\r\n"},

		// Multiple line message with one leading period removed.
		{"Line 1.\r\n..Line 2.\r\nLine 3.\r\n.\r\n", "Line 1.\r\n.Line 2.\r\nLine 3.\r\n"},
	}
	var buf bytes.Buffer
	s := &session{}
	s.srv = &Server{}
	s.br = bufio.NewReader(&buf)

	// Ensure readData() returns an EOF error on an empty buffer.
	_, err := s.readData()
	if err != io.EOF {
		t.Errorf("readData() on empty buffer returned err: %v, want EOF", err)
	}

	for _, tt := range tests {
		buf.Write([]byte(tt.lines))
		data, err := s.readData()
		if err != nil {
			t.Errorf("readData(%v) returned err: %v", tt.lines, err)
		} else if string(data) != tt.data {
			t.Errorf("readData(%v) returned %v, want %v", tt.lines, string(data), tt.data)
		}
	}
}

// Utility function for parsing extensions listed as service extensions in response to an EHLO command.
func parseExtensions(t *testing.T, greeting string) map[string]string {
	extensions := make(map[string]string)
	lines := strings.Split(greeting, "\n")

	if len(lines) > 1 {
		iLast := len(lines) - 1
		for i, line := range lines {
			prefix := line[0:4]

			// All but the last extension code prefix should be "250-".
			if i != iLast && prefix != "250-" {
				t.Errorf("Extension code prefix is %s, want '250-'", prefix)
			}

			// The last extension code prefix should be "250 ".
			if i == iLast && prefix != "250 " {
				t.Errorf("Extension code prefix is %s, want '250 '", prefix)
			}

			// Skip greeting line.
			if i == 0 {
				continue
			}

			// Add line as extension.
			line = strings.TrimSpace(line[4:]) // Strip code prefix and trailing \r\n
			if idx := strings.Index(line, " "); idx != -1 {
				extensions[line[:idx]] = line[idx+1:]
			} else {
				extensions[line] = ""
			}
		}
	}

	return extensions
}

// Test the extensions listed in response to an EHLO command.
func TestMakeEHLOResponse(t *testing.T) {
	s := &session{}
	s.srv = &Server{}

	// Greeting should be returned without trailing newlines.
	greeting := s.makeEHLOResponse()
	if len(greeting) != len(strings.TrimSpace(greeting)) {
		t.Errorf("EHLO greeting string has leading or trailing whitespace")
	}

	// By default, TLS is not configured, so STARTTLS should not appear.
	extensions := parseExtensions(t, s.makeEHLOResponse())
	if _, ok := extensions["STARTTLS"]; ok {
		t.Errorf("STARTTLS appears in the extension list when TLS is not configured")
	}

	// If TLS is configured, but not already in use, STARTTLS should appear.
	s.srv.TLSConfig = &tls.Config{}
	extensions = parseExtensions(t, s.makeEHLOResponse())
	if _, ok := extensions["STARTTLS"]; !ok {
		t.Errorf("STARTTLS does not appear in the extension list when TLS is configured")
	}

	// If TLS is already used on the connection, STARTTLS should not appear.
	s.tls = true
	extensions = parseExtensions(t, s.makeEHLOResponse())
	if _, ok := extensions["STARTTLS"]; ok {
		t.Errorf("STARTTLS appears in the extension list when TLS is already in use")
	}
}

// Benchmark the mail handling without the network stack introducing latency.
func BenchmarkReceive(b *testing.B) {
	clientConn, serverConn := net.Pipe()

	server := &Server{}
	session := server.newSession(serverConn)
	go session.serve()

	reader := bufio.NewReader(clientConn)
	_, _ = reader.ReadString('\n') // Read greeting message first.

	b.ResetTimer()

	// Benchmark a full mail transaction.
	for i := 0; i < b.N; i++ {
		fmt.Fprintf(clientConn, "%s\r\n", "HELO host.example.com")
		_, _ = reader.ReadString('\n')
		fmt.Fprintf(clientConn, "%s\r\n", "MAIL FROM:<sender@example.com>")
		_, _ = reader.ReadString('\n')
		fmt.Fprintf(clientConn, "%s\r\n", "RCPT TO:<recipient@example.com>")
		_, _ = reader.ReadString('\n')
		fmt.Fprintf(clientConn, "%s\r\n", "DATA")
		_, _ = reader.ReadString('\n')
		fmt.Fprintf(clientConn, "%s\r\n", "Test message.\r\n.")
		_, _ = reader.ReadString('\n')
		fmt.Fprintf(clientConn, "%s\r\n", "QUIT")
		_, _ = reader.ReadString('\n')
	}
}
