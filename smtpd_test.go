package smtpd

import (
	"bufio"
	"fmt"
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
	// MAIL with good FROM arg should return 250 Ok
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdRCPT(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// RCPT without preceeding MAIL should return 503 bad sequence
	cmdCode(t, conn, "RCPT", "503")

	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")

	// RCPT with no TO arg should return 501 syntax error
	cmdCode(t, conn, "RCPT", "501")
	// RCPT with empty TO arg should return 501 syntax error
	cmdCode(t, conn, "RCPT TO:", "501")
	// RCPT with good TO arg should return 250 Ok
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")

	// Multiple recipients with good TO arg should return 250 Ok
	cmdCode(t, conn, "RCPT TO:<recipient2@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient3@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient4@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient5@example.com>", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

func TestCmdDATA(t *testing.T) {
	conn := newConn(t)
	cmdCode(t, conn, "EHLO host.example.com", "250")

	// DATA without preceeding MAIL & RCPT should return 503 bad sequence
	cmdCode(t, conn, "DATA", "503")

	// Test a full mail transaction.
	cmdCode(t, conn, "MAIL FROM:<sender@example.com>", "250")
	cmdCode(t, conn, "RCPT TO:<recipient@example.com>", "250")
	cmdCode(t, conn, "DATA", "354")
	cmdCode(t, conn, "Test message.\r\n.", "250")

	cmdCode(t, conn, "QUIT", "221")
	conn.Close()
}

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
