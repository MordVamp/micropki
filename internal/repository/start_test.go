package repository

import (
	"testing"
	"time"
)

func TestStart(t *testing.T) {
	srv := &Server{
		Host: "127.0.0.1",
		Port: 0,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	time.Sleep(100 * time.Millisecond)

	select {
	case err := <-errCh:
		t.Fatalf("Start failed: %v", err)
	default:
		// Success
	}
}
