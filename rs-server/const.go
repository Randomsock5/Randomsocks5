package main

import (
	"github.com/codahale/chacha20"
)

const (
	ConnDefaultAddr string = ""
	ConnDefaultPort int    = 9500
	ConnDefaultType string = "tcp"
	DefaultPasswd   string = "hello world"
	KeySize         int    = chacha20.KeySize
	XNonceSize      int    = chacha20.XNonceSize
)
