package cipherPipe

import (
	"crypto/cipher"
	"io"
)

type CipherPipeReader struct {
	p *io.PipeReader
}

func (cr *CipherPipeReader) Close() error {
	return cr.p.Close()
}

func (cr *CipherPipeReader) CloseWithError(err error) error {
	return cr.p.CloseWithError(err)
}

func (cr *CipherPipeReader) Read(data []byte) (int, error) {
	return cr.p.Read(data)
}

type CipherPipeWrite struct {
	p  *io.PipeWriter
	cs cipher.Stream
}

func (cw *CipherPipeWrite) Close() error {
	return cw.p.Close()
}

func (cw *CipherPipeWrite) CloseWithError(err error) error {
	return cw.p.CloseWithError(err)
}

func (cw *CipherPipeWrite) Write(data []byte) (int, error) {
	wdata := make([]byte, len(data))
	cw.cs.XORKeyStream(wdata, data)
	return cw.p.Write(wdata)
}

// CipherPipeWrite write src or dst ,CipherPipeReader reader dst or src
func Pipe(cs cipher.Stream) (*CipherPipeReader, *CipherPipeWrite) {
	r, w := io.Pipe()

	cr := &CipherPipeReader{r}
	cw := &CipherPipeWrite{w, cs}
	return cr, cw
}
