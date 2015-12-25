package simpleSocks5

import (
	"fmt"
	"net"
	"io"
	"strings"
	"sync"
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
	target.SetKeepAlive(false)
	defer target.Close()

	// Send success
	local := target.LocalAddr().(*net.TCPAddr)
	bind  := AddrSpec{IP: local.IP, Port: local.Port}
	if err := sendReply(wd, successReply, &bind); err != nil {
		return fmt.Errorf("Failed to send reply: %v", err)
	}

	// Start proxying
	var done sync.WaitGroup
	finish := make(chan bool,4)

	go proxy( target, rd, done, finish)
	go proxy( wd, target, done, finish)

	// Wait
	done.Wait()
	return nil
}

func proxy(dst io.WriteCloser, src io.Reader, done sync.WaitGroup, finish chan bool) {
	done.Add(1)
	copyeof := make(chan struct{})
	go func ()  {
		io.Copy(dst, src)
		close(copyeof)
	}()
		
	select {
	case <- copyeof:
	case <- finish:
	}

	finish <- true
	done.Done()
}
