package ratelimit

import (
	"net"
	"testing"
)

func TestHTBListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	limited := LimitListener(l, 10.0, 5)

	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
		if err == nil {
			conn.Close()
		}
	}()

	conn, err := limited.Accept()
	if err != nil {
		t.Fatalf("Accept failed: %v", err)
	}
	conn.Close()
	limited.Close()
}
