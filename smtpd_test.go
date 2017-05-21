package smtpd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// Create test server to run commands against.
// Sleep to give ListenAndServe time to finishing listening before creating clients.
// This seems to only be necessary since Go 1.5.
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
	// Send HELO, expect greeting.
	cmdCode(t, newConn(t), "HELO host.example.com", "250")
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
