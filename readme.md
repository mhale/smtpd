# smtpd 

An SMTP server package written in Go, in the style of the built-in HTTP server. It meets the minimum requirements specified by RFC 2821 & 5321. 

It is based on [Brad Fitzpatrick's go-smtpd](https://github.com/bradfitz/go-smtpd). The differences can be summarised as:

* A simplified message handler
* Changes made for RFC compliance
* Testing has been added
* Code refactoring

## Features

* A single message handler for simple mail handling with native data types.
* RFC compliance. It implements the minimum command set, responds to commands and adds a valid Received header to messages as specified in RFC 2821 & 5321.
* Customisable listening address and port. It defaults to listening on all addresses on port 25 if unset.
* Customisable host name and application name. It defaults to the system hostname and "smtpd" application name if they are unset.

## Usage

In general: create the server and pass a handler function to it as for the HTTP server. The server function has the following definition:

```
func ListenAndServe(addr string, handler Handler, appname string, hostname string) error
```

The handler function must have the following definition:

```
func handler(remoteAddr net.Addr, from string, to []string, data []byte) 
```

The parameters are:

* remoteAddr: remote end of the TCP connection i.e. the mail client's IP address and port.
* from: the email address sent by the client in the MAIL command.
* to: the set of email addresses sent by the client in the RCPT command.
* data: the raw bytes of the mail message.

## Example

The following example code creates a new server with the name "MyServerApp" that listens on the localhost address and port 2525. Upon receipt of a new mail message, the handler function parses the mail and prints the subject header.


```
package main

import (
	"bytes"
	"log"
	"net"
	"net/mail"

	"github.com/mhale/smtpd"
)

func mailHandler(origin net.Addr, from string, to []string, data []byte) {
	msg, _ := mail.ReadMessage(bytes.NewReader(data))
	subject := msg.Header.Get("Subject")
	log.Printf("Received mail from %s for %s with subject %s", from, to[0], subject)
}

func main() {
	smtpd.ListenAndServe("127.0.0.1:2525", mailHandler, "MyServerApp", "")
}
```

## Testing

The tests cover the supported SMTP command set and line parsing. A single server is created listening on an ephemeral port (52525) for the duration of the tests. Each test creates a new client connection for processing commands.

## Licensing

Some of the code in this package was copied or adapted from code found in [Brad Fitzpatrick's go-smtpd](https://github.com/bradfitz/go-smtpd). As such, those sections of code are subject to their original copyright and license. The remaining code is in the public domain.