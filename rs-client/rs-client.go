package main

import (
	randbytes "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"flag"
	"github.com/Randomsock5/Randomsocks5/cipherPipe"
	"github.com/Randomsock5/Randomsocks5/tool"
	"github.com/codahale/chacha20"
	"golang.org/x/crypto/poly1305"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	server   string
	sport    int
	local    string
	lport    int
	passwd   string
	pac_port int
	pac_file string
)

func init() {
	flag.StringVar(&server, "server", ConnDefaultServerAddr, "Set server addr")
	flag.IntVar(&sport, "sport", ConnDefaultServerPort, "Set server port")
	flag.StringVar(&local, "local", ConnDefaultLocalAddr, "Set local addr")
	flag.IntVar(&lport, "lport", ConnDefaultLocalPort, "Set local port")
	flag.StringVar(&pac_file, "pac", DefaultPACFilePath, "Set pac path")
	flag.IntVar(&pac_port, "pac_port", ConnDefaultPACPort, "Set pac port")
	flag.StringVar(&passwd, "passwd", DefaultPasswd, "Set passwd")
}

func main() {
	flag.Parse()

	//PAC
	if exist(pac_file) {
		b, err := ioutil.ReadFile(pac_file)
		if err != nil {
			log.Println("Can not read file: " + pac_file)
			os.Exit(1)
		}

		s := string(b[:])
		s = strings.Replace(s, ReplaceFlag, "SOCKS5 "+local+":"+strconv.Itoa(lport)+";", 1)

		mux := http.NewServeMux()
		mux.HandleFunc("/pac", func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, s)
		})
		go http.ListenAndServe(":"+strconv.Itoa(pac_port), mux)

		log.Println("pac uri: http://127.0.0.1" + ":" + strconv.Itoa(pac_port) + "/pac")
	} else {
		log.Println("Can not find file: " + pac_file)
		os.Exit(1)
	}

	//Proxy
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
	nonce := sha512.Sum512([]byte(timeCookie + passwd))

	es, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
	ds, err := chacha20.NewXChaCha(initKey[:], nonce[:XNonceSize])
	if err != nil {
		log.Println("Error chacha20 init:  ", err)
		return
	}

	pconn, err := net.Dial("tcp", server+":"+strconv.Itoa(sport))
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
	if randomDataLen < 32767 {
		randomDataLen = randomDataLen + 2984
	}

	randomData := make([]byte, randomDataLen+poly1305.TagSize)
	randbytes.Read(randomData)

	var mac [poly1305.TagSize]byte
	poly1305.Sum(&mac, randomData[:randomDataLen], &initKey)
	copy(randomData[randomDataLen:], mac[:])

	// Start proxying
	var done sync.WaitGroup
	finish := make(chan bool,4)
	defer close(finish)

	//Read the client data, encryption after sent to the server
	go proxy(pconn, enr, done, finish)
	// write random data head
	var wi = 0
	for wi < (randomDataLen + poly1305.TagSize) {
		w, err := enw.Write(randomData[wi:])
		if err != nil {
			return
		}
		wi += w
	}

	go proxy(enw, conn, done, finish)

	//Receive server data ,decryption after back to the client
	go proxy(dew, pconn, done, finish)
	go proxy(conn, der, done, finish)

	// Wait
	done.Wait()
}

func proxy(dst io.Writer , src io.Reader, done sync.WaitGroup,finish chan bool) {
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

func exist(filepath string) bool {
	_, err := os.Stat(filepath)
	return err == nil || os.IsExist(err)
}
