package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"github.com/codahale/chacha20"
	"testing"
)

func TestCrypto(t *testing.T) {
	passwd := "hello world"
	initKey := sha256.Sum256([]byte(passwd))
	nonce := sha512.Sum512_224([]byte(passwd))
	cs, err := chacha20.NewXChaCha(initKey[:], nonce[:chacha20.XNonceSize])
	ds, err := chacha20.NewXChaCha(initKey[:], nonce[:chacha20.XNonceSize])
	if err != nil {
		t.Errorf("Bad init")
	}
	dst := make([]byte, len(passwd))
	cs.XORKeyStream(dst, []byte(passwd))
	den := make([]byte, 4)
	ds.XORKeyStream(den, dst[:4])

	if !bytes.Equal([]byte("hell"), den) {
		t.Errorf("Bad Decoder")
	}
}
