package simpleSocks5

import (
	"fmt"
	"net"
	"io"
	"strings"
	"time"
)

// handleConnect is used to handle a connect command
func handleConnect(conn net.Conn, dest *AddrSpec) error {
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
		if err := sendReply(conn, resp, nil); err != nil {
			return fmt.Errorf("Failed to send reply: %v", err)
		}
		return fmt.Errorf("Connect to %v failed: %v", dest, err)
	}
	target.SetKeepAlive(false)
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind  := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(conn, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	finish := make(chan bool,2)

	go proxy( target, conn, finish)
	go proxy( conn, target, finish)

	// Wait
	select{
	case <- finish:
	}
	time.Sleep(2*time.Second)

	return nil
}

func proxy(dst io.Writer, src io.Reader, finish chan bool) {
	io.Copy(dst,src)

	time.Sleep(time.Second)
	finish <- true
}
