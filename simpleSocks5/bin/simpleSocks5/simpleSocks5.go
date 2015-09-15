package main

import(
    "net"
    "bufio"
    "log"
    "os"
    "github.com/Randomsocks5/Randomsocks5/simpleSocks5"
)

func main (){
    l, err := net.Listen("tcp", ":9850")
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

func handleRequest(conn net.Conn){
    bufConnR := bufio.NewReader(conn)
    simpleSocks5.Socks5Handle(bufConnR, conn)
}
