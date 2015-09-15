package simpleSocks5

import (
	"net"
)

func Resolve(name string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return nil, err
	}
	return addr.IP, err
}
