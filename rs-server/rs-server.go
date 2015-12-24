package main

import (
	"github.com/Randomsock5/Randomsocks5/cipherPipe"
	"github.com/Randomsock5/Randomsocks5/simpleSocks5"
	"github.com/Randomsock5/Randomsocks5/tool"
	"golang.org/x/crypto/poly1305"
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
	go func ()  {
		defer conn.Close()

		timeCookie := tool.GetTimeCookie()
		initKey := sha256.Sum256([]byte(passwd+timeCookie))
		nonce := sha512.Sum512([]byte(timeCookie + passwd))

		es, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
		ds, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
		if err != nil {
			log.Println("Error chacha20 init:  ", err)
			return
		}

		//random data head length
		randomDataLen, _ := tool.ReadInt(initKey[len(initKey)-2:])
		if randomDataLen < 32767 {
			randomDataLen = randomDataLen + 2984
		}

		finish := make(chan struct{})
		go proxy(conn, es, ds, finish, randomDataLen, &initKey)

		select {
		case  <- finish:
			close(finish)
			return
		}
	}()
}

func proxy( conn net.Conn, encodeStm, decodeStm cipher.Stream,finish chan struct{}, randomDataLen int, key *[32]byte) {
	der, dew := cipherPipe.Pipe(decodeStm)
	defer der.Close()
	defer dew.Close()
	enr, enw := cipherPipe.Pipe(encodeStm)
	defer enr.Close()
	defer enw.Close()

	go io.Copy(dew, conn)

	// read random data head
	var ri = 0
	var randomdata = make([]byte, randomDataLen + poly1305.TagSize)
	for ri < (randomDataLen + poly1305.TagSize) {
		r, err := der.Read(randomdata[ri:])
		if err != nil {
			finish<-struct{}{}
			return
		}
		ri += r
	}

	var mac [16]byte
	copy(mac[:],randomdata[randomDataLen:])
	if !poly1305.Verify(&mac, randomdata[:randomDataLen], key) {
		log.Println("poly1305 mac verify error")
		finish<-struct{}{}
		return
	}

	go io.Copy(conn, enr)

	simpleSocks5.Socks5Handle(der, enw)
  finish<-struct{}{}
}
