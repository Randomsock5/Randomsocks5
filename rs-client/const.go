package main

import (
	"github.com/codahale/chacha20"
)

const (
	ConnDefaultServerAddr string = "127.0.0.2"
	ConnDefaultServerPort int    = 9500
	ConnDefaultLocalAddr  string = "127.0.0.1"
	ConnDefaultLocalPort  int    = 9500
	ConnDefaultPACPort    int    = 9501
	ConnDefaultType       string = "tcp"
	DefaultPasswd         string = "hello world"
	DefaultPACFilePath    string = "pac.txt"
	KeySize               int    = chacha20.KeySize
	XNonceSize            int    = chacha20.XNonceSize
	ReplaceFlag						string = "__PROXY__"
)
