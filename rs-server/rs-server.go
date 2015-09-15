package main

import (
	"github.com/Randomsocks5/Randomsocks5/cipherPipe"
	"github.com/Randomsocks5/Randomsocks5/simpleSocks5"
	"github.com/Randomsocks5/Randomsocks5/tool"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"github.com/codahale/chacha20"
	"io"
	"log"
	"net"
	"os"
	"strconv"
)

var (
	addr   string
	port   int
	passwd string
)

func init() {
	flag.StringVar(&addr, "addr", ConnDefaultAddr, "Set Listen Addr")
	flag.IntVar(&port, "port", ConnDefaultPort, "Set Server Port")
	flag.StringVar(&passwd, "passwd", DefaultPasswd, "Set Passwd")
}

func main() {
	flag.Parse()

	l, err := net.Listen(ConnDefaultType, addr+":"+strconv.Itoa(port))
	if err != nil {
		log.Println("Error listening: ", err)
		os.Exit(1)
	}
	defer l.Close()

	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			log.Println("Error accepting:  ", err)
			continue
		}
		go handleRequest(conn)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	timeCookie := tool.GetTimeCookie()
	initKey := sha256.Sum256([]byte(passwd + timeCookie))
	nonce := sha512.Sum512_224([]byte(timeCookie + passwd))
	es, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
	ds, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
	if err != nil {
		log.Println("Error chacha20 init:  ", err)
		return
	}

	//Read random head data
	randomDataLen, err := tool.ReadInt(initKey[len(initKey)-2:])
	tool.SetReadTimeOut(15, conn)
	_, err = conn.Read(make([]byte, randomDataLen))
	if err != nil {
		log.Println("Error tcp read:  ", err)
		return
	}

	finish := make(chan struct{})
	go proxy(conn, es, ds,finish)

	select {
	case  <- finish:
		return
	}
}

func proxy( conn net.Conn, encodeStm, decodeStm cipher.Stream,finish chan struct{}) {
	der, dew := cipherPipe.Pipe(decodeStm)
	defer der.Close()
	defer dew.Close()
	enr, enw := cipherPipe.Pipe(encodeStm)
	defer enr.Close()
	defer enw.Close()

	go io.Copy(dew, conn)
	go io.Copy(conn, enr)

	simpleSocks5.Socks5Handle(der, enw)
    close(finish)
}