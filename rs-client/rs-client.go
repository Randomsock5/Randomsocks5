package main

import (
	randbytes "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"github.com/Randomsocks5/Randomsocks5/cipherPipe"
	"github.com/Randomsocks5/Randomsocks5/tool"
	"github.com/codahale/chacha20"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"
)

var (
	server string
	sport  int
	local  string
	lport  int
	passwd string
)

func init() {
	flag.StringVar(&server, "server", ConnDefaultServerAddr, "Set Server Addr")
	flag.IntVar(&sport, "sport", ConnDefaultServerPort, "Set Server Port")
	flag.StringVar(&local, "local", ConnDefaultLocalAddr, "Set Local Addr")
	flag.IntVar(&lport, "lport", ConnDefaultLocalPort, "Set Local Port")
	flag.StringVar(&passwd, "passwd", DefaultPasswd, "Set Passwd")
}

func main() {
	flag.Parse()

	l, err := net.Listen(ConnDefaultType, local+":"+strconv.Itoa(lport))
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

	sconn, err := net.Dial("tcp", server+":"+strconv.Itoa(sport))
	if err != nil {
		log.Println("Create connection failed :", err)
		return
	}

	der, dew := cipherPipe.Pipe(ds)
	defer der.Close()
	defer dew.Close()
	enr, enw := cipherPipe.Pipe(es)
	defer enr.Close()
	defer enw.Close()

	randomDataLen, _ := tool.ReadInt(initKey[len(initKey)-2:])
	randomData := make([]byte, randomDataLen)
	randbytes.Read(randomData)

	// Start proxying
	errorCh := make(chan error, 4)
	//Read the client data, encryption after sent to the server
	go proxy(sconn, enr, errorCh)
	// write random data head
	enw.Write(randomData)
	go proxy(enw, conn, errorCh)

	//Receive server data ,decryption after back to the client
	go proxy(dew, sconn, errorCh)
	go proxy(conn, der, errorCh)

	// Wait
	select {
	case e := <-errorCh:
		if e != nil {
			log.Println(e)
		}
		return
	}
}

func proxy(dst io.Writer, src io.Reader, errorCh chan error) {
	_, err := io.Copy(dst, src)
	time.Sleep(10 * time.Millisecond)
	errorCh <- err
}
