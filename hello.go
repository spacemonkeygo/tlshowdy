// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// 2015 modifications by Space Monkey, Inc.

package tlshowdy

const (
	extensionServerName      = 0
	extensionNextProtoNeg    = 13172
	extensionSupportedPoints = 11
	extensionSessionTicket   = 35
	extensionALPN            = 16
)

// ClientHelloMsg is a Go struct version of the TLS client hello message.
type ClientHelloMsg struct {
	Vers               uint16
	Random             []byte
	SessionId          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
	NextProtoNeg       bool
	ServerName         string
	SupportedPoints    []uint8
	TicketSupported    bool
	SessionTicket      []uint8
	ALPNProtocols      []string
}

func (m *ClientHelloMsg) Unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.Vers = uint16(data[4])<<8 | uint16(data[5])
	m.Random = data[6:38]
	sessionIdLen := int(data[38])
	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
		return false
	}
	m.SessionId = data[39 : 39+sessionIdLen]
	data = data[39+sessionIdLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen is the number of bytes of cipher suite numbers. Since
	// they are uint16s, the number must be even.
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.CipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.CipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.CompressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.NextProtoNeg = false
	m.ServerName = ""
	m.TicketSupported = false
	m.SessionTicket = nil
	m.ALPNProtocols = nil

	if len(data) == 0 {
		// ClientHello is optionally followed by extension data
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			if length < 2 {
				return false
			}
			numNames := int(data[0])<<8 | int(data[1])
			d := data[2:]
			for i := 0; i < numNames; i++ {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.ServerName = string(d[0:nameLen])
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return false
			}
			m.NextProtoNeg = true
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.SupportedPoints = make([]uint8, l)
			copy(m.SupportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.TicketSupported = true
			m.SessionTicket = data[:length]
		case extensionALPN:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				m.ALPNProtocols = append(m.ALPNProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		}
		data = data[length:]
	}

	return true
}

func (m *ClientHelloMsg) Marshal() []byte {
	length := 2 + 32 + 1 + len(m.SessionId) + 2 + len(m.CipherSuites)*2 + 1 + len(m.CompressionMethods)
	numExtensions := 0
	extensionsLength := 0
	if m.NextProtoNeg {
		numExtensions++
	}
	if len(m.ServerName) > 0 {
		extensionsLength += 5 + len(m.ServerName)
		numExtensions++
	}
	if len(m.SupportedPoints) > 0 {
		extensionsLength += 1 + len(m.SupportedPoints)
		numExtensions++
	}
	if m.TicketSupported {
		extensionsLength += len(m.SessionTicket)
		numExtensions++
	}
	if len(m.ALPNProtocols) > 0 {
		extensionsLength += 2
		for _, s := range m.ALPNProtocols {
			if l := len(s); l == 0 || l > 255 {
				panic("invalid ALPN protocol")
			}
			extensionsLength++
			extensionsLength += len(s)
		}
		numExtensions++
	}
	if numExtensions > 0 {
		extensionsLength += 4 * numExtensions
		length += 2 + extensionsLength
	}

	x := make([]byte, 4+length)
	x[0] = typeClientHello
	x[1] = uint8(length >> 16)
	x[2] = uint8(length >> 8)
	x[3] = uint8(length)
	x[4] = uint8(m.Vers >> 8)
	x[5] = uint8(m.Vers)
	copy(x[6:38], m.Random)
	x[38] = uint8(len(m.SessionId))
	copy(x[39:39+len(m.SessionId)], m.SessionId)
	y := x[39+len(m.SessionId):]
	y[0] = uint8(len(m.CipherSuites) >> 7)
	y[1] = uint8(len(m.CipherSuites) << 1)
	for i, suite := range m.CipherSuites {
		y[2+i*2] = uint8(suite >> 8)
		y[3+i*2] = uint8(suite)
	}
	z := y[2+len(m.CipherSuites)*2:]
	z[0] = uint8(len(m.CompressionMethods))
	copy(z[1:], m.CompressionMethods)

	z = z[1+len(m.CompressionMethods):]
	if numExtensions > 0 {
		z[0] = byte(extensionsLength >> 8)
		z[1] = byte(extensionsLength)
		z = z[2:]
	}
	if m.NextProtoNeg {
		z[0] = byte(extensionNextProtoNeg >> 8)
		z[1] = byte(extensionNextProtoNeg & 0xff)
		// The length is always 0
		z = z[4:]
	}
	if len(m.ServerName) > 0 {
		z[0] = byte(extensionServerName >> 8)
		z[1] = byte(extensionServerName & 0xff)
		l := len(m.ServerName) + 5
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]

		// RFC 3546, section 3.1
		//
		// struct {
		//     NameType name_type;
		//     select (name_type) {
		//         case host_name: HostName;
		//     } name;
		// } ServerName;
		//
		// enum {
		//     host_name(0), (255)
		// } NameType;
		//
		// opaque HostName<1..2^16-1>;
		//
		// struct {
		//     ServerName server_name_list<1..2^16-1>
		// } ServerNameList;

		z[0] = byte((len(m.ServerName) + 3) >> 8)
		z[1] = byte(len(m.ServerName) + 3)
		z[3] = byte(len(m.ServerName) >> 8)
		z[4] = byte(len(m.ServerName))
		copy(z[5:], []byte(m.ServerName))
		z = z[l:]
	}
	if len(m.SupportedPoints) > 0 {
		// http://tools.ietf.org/html/rfc4492#section-5.5.2
		z[0] = byte(extensionSupportedPoints >> 8)
		z[1] = byte(extensionSupportedPoints)
		l := 1 + len(m.SupportedPoints)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		l--
		z[4] = byte(l)
		z = z[5:]
		for _, pointFormat := range m.SupportedPoints {
			z[0] = byte(pointFormat)
			z = z[1:]
		}
	}
	if m.TicketSupported {
		// http://tools.ietf.org/html/rfc5077#section-3.2
		z[0] = byte(extensionSessionTicket >> 8)
		z[1] = byte(extensionSessionTicket)
		l := len(m.SessionTicket)
		z[2] = byte(l >> 8)
		z[3] = byte(l)
		z = z[4:]
		copy(z, m.SessionTicket)
		z = z[len(m.SessionTicket):]
	}
	if len(m.ALPNProtocols) > 0 {
		z[0] = byte(extensionALPN >> 8)
		z[1] = byte(extensionALPN & 0xff)
		lengths := z[2:]
		z = z[6:]

		stringsLength := 0
		for _, s := range m.ALPNProtocols {
			l := len(s)
			z[0] = byte(l)
			copy(z[1:], s)
			z = z[1+l:]
			stringsLength += 1 + l
		}

		lengths[2] = byte(stringsLength >> 8)
		lengths[3] = byte(stringsLength)
		stringsLength += 2
		lengths[0] = byte(stringsLength >> 8)
		lengths[1] = byte(stringsLength)
	}

	return x
}
