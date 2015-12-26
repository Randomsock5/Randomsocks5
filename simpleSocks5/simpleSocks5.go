package simpleSocks5

import (
	"fmt"
	"log"
	"io"
	"net"
)

func Socks5Handle(conn net.Conn) {
	// Read the version byte
	version := []byte{0}
	if _, err := conn.Read(version); err != nil {
		log.Printf("socks: Failed to get version byte: %v", err)
		return
	}

	// Ensure we are compatible
	if version[0] != socks5Version {
		err := fmt.Errorf("Unsupported SOCKS version: %v", version)
		log.Printf("socks: %v", err)
		return
	}

	// authenticate is used to handle connection authentication
	_, err := readMethods(conn)
	if err != nil {
		log.Printf("Failed to get auth methods: %v", err)
		return
	}

	_, err = conn.Write([]byte{socks5Version, noAuth})
	if err != nil {
		log.Printf("Failed : %v", err)
		return
	}
	handleRequest(conn)
}

func handleRequest(conn net.Conn ) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(conn, header, 3); err != nil {
		log.Printf("Failed to get command version: %v", err)
		return
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		log.Printf("Unsupported command version: %v", header[0])
		return
	}

	// Read in the destination address
	dest, err := readAddrSpec(conn)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(conn, addrTypeNotSupported, nil); err != nil {
				log.Printf("Failed to send reply: %v", err)
				return
			}
		}
		log.Printf("Failed to read destination address: %v", err)
		return
	}

	// Resolve the address if we have a FQDN
	if dest.FQDN != "" {
		addr, err := Resolve(dest.FQDN)
		if err != nil {
			if err := sendReply(conn, hostUnreachable, nil); err != nil {
				log.Printf("Failed to send reply: %v", err)
				return
			}
			log.Printf("Failed to resolve destination '%v': %v", dest.FQDN, err)
			return
		}
		dest.IP = addr
	}

	// Switch on the command
	switch header[1] {
	case connectCommand:
		if err = handleConnect(conn, dest); err != nil {
			log.Printf("Failed to connect: %s", err)
		}
		return
	default:
		if err := sendReply(conn, commandNotSupported, nil); err != nil {
			log.Printf("Failed to send reply: %v", err)
			return
		}
		log.Printf("Unsupported command: %v", header[1])
		return
	}
}
