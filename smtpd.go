// SMTP server package.
package smtpd

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"time"
)

var (
	rcptToRE    = regexp.MustCompile(`[Tt][Oo]:<(.+)>`)
	mailFromRE  = regexp.MustCompile(`[Ff][Rr][Oo][Mm]:<(.*)>`) // Delivery Status Notifications are sent with "MAIL FROM:<>"
)

// Definition of handler function.
type Handler func(remoteAddr net.Addr, from string, to []string, data []byte)

// ListenAndServe listens on the TCP network address addr
// and then calls Serve with handler to handle requests
// on incoming connections.
func ListenAndServe(addr string, handler Handler, appname string, hostname string) error {
	srv := &Server{Addr: addr, Handler: handler, Appname: appname, Hostname: hostname}
	return srv.ListenAndServe()
}

// Server is an SMTP server.
type Server struct {
	Addr    string // TCP address to listen on, defaults to ":25" (all addresses, port 25) if empty
	Handler Handler
	Appname string
	Hostname string
}

// ListenAndServe listens on the TCP network address srv.Addr and then
// calls Serve to handle requests on incoming connections.  If
// srv.Addr is blank, ":25" is used.
func (srv *Server) ListenAndServe() error {
	if srv.Addr == "" {
		srv.Addr = ":25"
	}
	if srv.Appname == "" {
		srv.Appname = "smtpd"
	}
	if srv.Hostname == "" {
		srv.Hostname, _ = os.Hostname()
	}
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

func (srv *Server) Serve(ln net.Listener) error {
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				log.Printf("%s: Accept error: %v", srv.Appname, err)
				continue
			}
			return err
		}
		session, err := srv.newSession(conn)
		if err != nil {
			continue
		}
		go session.serve()
	}
}

type session struct {
	srv        *Server
	conn       net.Conn
	br         *bufio.Reader
	bw         *bufio.Writer
	remoteIP   string // Remote IP address
	remoteHost string // Remote hostname according to reverse DNS lookup
	remoteName string // Remote hostname as supplied with EHLO
}

// Create new session from connection.
func (srv *Server) newSession(conn net.Conn) (s *session, err error) {
	s = &session{
		srv:  srv,
		conn: conn,
		br:   bufio.NewReader(conn),
		bw:   bufio.NewWriter(conn),
	}
	return
}

// Function called to handle connection requests.
func (s *session) serve() {
	defer s.conn.Close() 
	var from string
	var to []string
	var buffer bytes.Buffer

	// Get remote end info for the Received header.
	s.remoteIP, _, _ = net.SplitHostPort(s.conn.RemoteAddr().String())
	names, _ := net.LookupAddr(s.remoteIP)
	if len(names) > 0 {
		s.remoteHost = names[0]
	}

	// Send banner.
	s.writef("220 %s %s SMTP Service ready", s.srv.Hostname, s.srv.Appname)

loop:
	for {
		// Attempt to read a line from the socket.
		// On error, assume the client has gone away i.e. return from serve().
		line, err := s.readLine()
		if err != nil {
			break
		}
		verb, args := s.parseLine(line)

		switch verb {
		case "EHLO", "HELO":
			s.remoteName = args
			s.writef("250 %s greets %s", s.srv.Hostname, s.remoteName)

			// RFC 2821 section 4.1.4 specifies that EHLO has the same effect as RSET.
			from = ""
			to = nil
			buffer.Reset()
		case "MAIL":
			match := mailFromRE.FindStringSubmatch(args)
			if match == nil {
				s.writef("501 Syntax error in parameters or arguments (invalid FROM parameter)")
			} else {
				from = match[1]
				s.writef("250 Ok")
			}
			to = nil
			buffer.Reset()
		case "RCPT":
			if from == "" {
				s.writef("503 Bad sequence of commands (MAIL required before RCPT)")
				break
			}

			match := rcptToRE.FindStringSubmatch(args)
			if match == nil {
				s.writef("501 Syntax error in parameters or arguments (invalid TO parameter)")
			} else {
				// RFC 5321 specifies 100 minimum recipients
				if len(to) == 100 {
					s.writef("452 Too many recipients")
				} else {
					to = append(to, match[1])
					s.writef("250 Ok")
				}
			}
		case "DATA":
			if from == "" || to == nil {
				s.writef("503 Bad sequence of commands (MAIL & RCPT required before DATA)")
				break
			}

			s.writef("354 Start mail input; end with <CR><LF>.<CR><LF>")

			// Attempt to read message body from the socket.
			// On error, assume the client has gone away i.e. return from serve().
			data, err := s.readData()
			if err != nil {
				break loop
			}

			// Create Received header & write message body into buffer.
			buffer.Reset()
			buffer.Write(s.makeHeaders(to))
			buffer.Write(data)
			s.writef("250 Ok: queued")

			// Pass mail on to handler.
			if s.srv.Handler != nil {
				go s.srv.Handler(s.conn.RemoteAddr(), from, to, buffer.Bytes())
			}

			// Reset for next mail.
			from = ""
			to = nil
			buffer.Reset()
		case "QUIT":
			s.writef("221 %s %s SMTP Service closing transmission channel", s.srv.Hostname, s.srv.Appname)
			break loop
		case "RSET":
			s.writef("250 Ok")
			from = ""
			to = nil
			buffer.Reset()
		case "NOOP":
			s.writef("250 Ok")
		case "HELP", "VRFY", "EXPN":
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 reply codes
			s.writef("502 Command not implemented")
		default:
			// See RFC 5321 section 4.2.4 for usage of 500 & 502 reply codes
			s.writef("500 Syntax error, command unrecognized")
		}
	}
}

// Wrapper function for writing a complete line to the socket.
func (s *session) writef(format string, args ...interface{}) {
	fmt.Fprintf(s.bw, format+"\r\n", args...)
	s.bw.Flush()
}

// Read a complete line from the socket.
func (s *session) readLine() (string, error) {
	line, err := s.br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line) // Strip trailing \r\n
	return line, err
}

// Parse a line read from the socket.
func (s *session) parseLine(line string) (verb string, args string) {
	if idx := strings.Index(line, " "); idx != -1 {
		verb = strings.ToUpper(line[:idx])
		args = strings.TrimSpace(line[idx+1 : len(line)])
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}
	return verb, args
}

// Read the message data following a DATA command.
func (s *session) readData() ([]byte, error) {
	var data []byte
	for {
		slice, err := s.br.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		// Handle end of data denoted by lone period (\r\n.\r\n)
		if bytes.Equal(slice, []byte(".\r\n")) {
			break
		}
		// Remove leading period (RFC 5321 section 4.5.2)
		if slice[0] == '.' {
			slice = slice[1:]
		}
		data = append(data, slice...)
	}
	return data, nil
}

// Create the Received header to comply with RFC 2821 section 3.8.2.
// TODO: Work out what to do with multiple to addresses.
func (s *session) makeHeaders(to []string) []byte {
	var buffer bytes.Buffer
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	buffer.WriteString(fmt.Sprintf("Received: from %s (%s [%s])\r\n", s.remoteName, s.remoteHost, s.remoteIP))
	buffer.WriteString(fmt.Sprintf("        by %s (%s) with SMTP\r\n", s.srv.Hostname, s.srv.Appname))
	buffer.WriteString(fmt.Sprintf("        for <%s>; %s\r\n", to[0], now))
	return buffer.Bytes()
}
