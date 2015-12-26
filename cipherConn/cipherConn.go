package cipherConn

import (
	"crypto/cipher"
	"net"
  "time"
)

type CipherConn struct {
  conn   net.Conn
  decode cipher.Stream
  encode cipher.Stream
  TimeOut time.Duration
}

func (cc *CipherConn) Write(b []byte) (n int,err error) {
  buf := make([]byte, len(b))
  cc.encode.XORKeyStream(buf, b)

  cc.SetWriteDeadline(time.Now().Add(cc.TimeOut*time.Second))
  n, err = cc.conn.Write(buf)

  return n,err
}

func (cc *CipherConn) Read(b []byte) (n int,err error){
  buf := make([]byte, len(b))

  cc.SetReadDeadline(time.Now().Add(cc.TimeOut*time.Second))
  n,err = cc.conn.Read(buf)

  if err == nil {
    cc.decode.XORKeyStream(b[:n],buf[:n])
  }

  return n,err
}

func (cc *CipherConn) Close() error{
  return cc.conn.Close()
}

func (cc *CipherConn) LocalAddr() net.Addr {
  return cc.conn.LocalAddr()
}

func (cc *CipherConn) RemoteAddr() net.Addr {
  return cc.conn.RemoteAddr()
}

func (cc *CipherConn) SetDeadline(t time.Time) error {
  return cc.conn.SetDeadline(t)
}

func (cc *CipherConn) SetReadDeadline(t time.Time) error {
  return cc.conn.SetReadDeadline(t)
}

func (cc *CipherConn) SetWriteDeadline(t time.Time) error {
  return cc.conn.SetWriteDeadline(t)
}

func NewCipherConn(de,en cipher.Stream,conn net.Conn) *CipherConn  {
  return &CipherConn{
    conn:conn,
    decode:de,
    encode:en,
    TimeOut:30,
  }
}
