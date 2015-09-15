package simpleSocks5

import (
	"io"
    "time"
)

// proxy is used to suffle data from src to destination, and sends errors
// down a dedicated channel
func proxy(dst io.Writer, src io.Reader, errorCh chan error) {
	// Copy
	_, err := io.Copy(dst, src)
	// Log, and sleep. This is jank but allows the otherside
	// to finish a pending copy
	time.Sleep(10 * time.Millisecond)

	// Send any errors
	errorCh <- err
}
