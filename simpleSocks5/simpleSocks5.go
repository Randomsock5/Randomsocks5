package simpleSocks5

import (
	"fmt"
	"log"
	"io"
)

func Socks5Handle(rd io.Reader, wd io.Writer) {
	// Read the version byte
	version := []byte{0}
	if _, err := rd.Read(version); err != nil {
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
	_, err := readMethods(rd)
	if err != nil {
		log.Printf("Failed to get auth methods: %v", err)
		return
	}

	_, err = wd.Write([]byte{socks5Version, noAuth})
	if err != nil {
		log.Printf("Failed : %v", err)
		return
	}
	handleRequest(rd, wd)
}

func handleRequest(rd io.Reader, wd io.Writer) {
	// Read the version byte
	header := []byte{0, 0, 0}
	if _, err := io.ReadAtLeast(rd, header, 3); err != nil {
		log.Printf("Failed to get command version: %v", err)
		return
	}

	// Ensure we are compatible
	if header[0] != socks5Version {
		log.Printf("Unsupported command version: %v", header[0])
		return
	}

	// Read in the destination address
	dest, err := readAddrSpec(rd)
	if err != nil {
		if err == unrecognizedAddrType {
			if err := sendReply(wd, addrTypeNotSupported, nil); err != nil {
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
			if err := sendReply(wd, hostUnreachable, nil); err != nil {
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
		if err = handleConnect(wd, rd, dest); err != nil {
			log.Printf("Failed to connect: %s", err)
		}
		return
	default:
		if err := sendReply(wd, commandNotSupported, nil); err != nil {
			log.Printf("Failed to send reply: %v", err)
			return
		}
		log.Printf("Unsupported command: %v", header[1])
		return
	}
}
