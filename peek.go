// package tlshowdy contains a number of utilities all designed to implement
// one primary method, Peek, which allows for simple implementations of
// virtual host demultiplexing using SNI.
package tlshowdy

import (
	"net"
)

// Peek takes a net.Conn and reads a TLS client hello message if possible.
// The returned conn is a net.Conn that has whatever Peek read during
// processing placed back at the front of the read stream. If no client hello
// was detected but no other read error occurred, a nil ClientHelloMsg will
// be returned.
func Peek(conn net.Conn) (*ClientHelloMsg, net.Conn, error) {
	rr := NewRecordingReader(conn)
	hello, err := Read(rr)
	if err != nil {
		return nil, nil, err
	}
	return hello, NewPrefixConn(rr.Received, conn), nil
}
