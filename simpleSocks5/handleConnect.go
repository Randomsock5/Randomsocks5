package simpleSocks5

import (
	"fmt"
	"net"
	"io"
	"strings"
)

// handleConnect is used to handle a connect command
func handleConnect(wd io.Writer, rd io.Reader, dest *AddrSpec) error {
	// Attempt to connect
	addr := net.TCPAddr{IP: dest.IP, Port: dest.Port}
	target, err := net.DialTCP("tcp", nil, &addr)
	if err != nil {
		msg := err.Error()
		resp := hostUnreachable
		if strings.Contains(msg, "refused") {
			resp = connectionRefused
		} else if strings.Contains(msg, "network is unreachable") {
			resp = networkUnreachable
		}
		if err := sendReply(wd, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", dest, err)
	}
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(wd, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	errorCh := make(chan error, 2)
	go proxy( target, rd, errorCh)
	go proxy( wd, target, errorCh)

	// Wait
	select {
	case e := <-errorCh:
		return e
	}
}
