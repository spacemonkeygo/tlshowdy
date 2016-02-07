package tlshowdy

import (
	"bytes"
	"io"
	"net"
)

// PrefixConn wraps a net.Conn but attaches a prefixed amount of data to the
// incoming side. This is used by Peek to replace consumed data.
type PrefixConn struct {
	net.Conn
	reader io.Reader
}

func NewPrefixConn(prefix []byte, conn net.Conn) *PrefixConn {
	return &PrefixConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(prefix), conn),
	}
}

func (c *PrefixConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func (c *PrefixConn) UnderlyingConn() net.Conn { return c.Conn }

// RecordingReader wraps another io.Reader but keeps track of what it has
// read so far.
type RecordingReader struct {
	r        io.Reader
	Received []byte
}

func NewRecordingReader(r io.Reader) *RecordingReader {
	return &RecordingReader{
		r: r}
}

func (r *RecordingReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.Received = append(r.Received, p[:n]...)
	return n, err
}
