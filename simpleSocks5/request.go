package simpleSocks5

import (
	"fmt"
	"io"
	"net"
)

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// readAddrSpec is used to read AddrSpec.
// Expects an address type byte, follwed by the address and port
func readAddrSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	// Get the address type
	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per type basis
	switch addrType[0] {
	case ipv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case ipv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = net.IP(addr)

	case fqdnAddress:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, unrecognizedAddrType
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}


// sendReply is used to send a reply message
func sendReply(w io.Writer, resp uint8, addr *AddrSpec) error {
	// Format the address
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = ipv4Address
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = fqdnAddress
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = ipv4Address
		addrBody = []byte(addr.IP.To4())
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = ipv6Address
		addrBody = []byte(addr.IP.To16())
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("Failed to format address: %v", addr)
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = socks5Version
	msg[1] = resp
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := w.Write(msg)
	return err
}
