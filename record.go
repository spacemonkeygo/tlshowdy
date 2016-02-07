package tlshowdy

import (
	"io"
)

const (
	recordHeaderLen     = 5
	recordTypeHandshake = 22
	maxCiphertext       = 16384 + 2048
	maxHandshake        = 65536
	typeClientHello     = 1
)

// ReadRecord reads a single TLS record.
func ReadRecord(r io.Reader) (record []byte, is_ssl bool,
	err error) {
	header := make([]byte, recordHeaderLen)
	_, err = io.ReadFull(r, header)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return nil, false, err
	}

	typ := header[0]

	if typ != recordTypeHandshake {
		return nil, false, nil
	}

	version := uint16(header[1])<<8 | uint16(header[2])
	ciphertext_len := int(header[3])<<8 | int(header[4])
	if ciphertext_len > maxCiphertext {
		return nil, false, nil
	}
	if version >= 0x1000 || ciphertext_len >= 0x3000 {
		return nil, false, nil
	}

	payload := make([]byte, ciphertext_len)
	_, err = io.ReadFull(r, payload)
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			err = io.EOF
		}
		return nil, false, err
	}

	return payload, true, nil
}

// ReadHandshake reads an incoming TLS handshake message
func ReadHandshake(r io.Reader) (data []byte, is_ssl bool,
	err error) {

	for len(data) < 4 {
		record, is_ssl, err := ReadRecord(r)
		if err != nil || !is_ssl {
			return nil, false, err
		}
		data = append(data, record...)
	}

	handshake_len := int(data[1])<<16 | int(data[2])<<8 |
		int(data[3])
	if handshake_len > maxHandshake {
		return nil, false, nil
	}

	for len(data) < 4+handshake_len {
		record, is_ssl, err := ReadRecord(r)
		if err != nil || !is_ssl {
			return nil, false, err
		}
		data = append(data, record...)
	}

	return data[:4+handshake_len], true, nil
}

// Read reads a full TLS client hello
func Read(r io.Reader) (msg *ClientHelloMsg, err error) {
	handshake, is_ssl, err := ReadHandshake(r)
	if err != nil || !is_ssl {
		return nil, err
	}

	if handshake[0] != typeClientHello {
		return nil, nil
	}

	m := &ClientHelloMsg{}
	if !m.Unmarshal(handshake) {
		return nil, nil
	}

	return m, nil
}

// PrefixLength is the number of bytes required to determine if the connection
// is a TLS connection.
const PrefixLength = 1

// PrefixIsTLS will return if an incoming connection is, in fact, likely to be
// a TLS connection.
func PrefixIsTLS(prefix []byte) bool {
	return len(prefix) > 0 && prefix[0] == recordTypeHandshake
}
