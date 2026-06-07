package ratelimit

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockListener struct {
	conns chan net.Conn
	err   error
}

func (m *mockListener) Accept() (net.Conn, error) {
	if m.err != nil {
		return nil, m.err
	}
	return <-m.conns, nil
}
func (m *mockListener) Close() error   { return nil }
func (m *mockListener) Addr() net.Addr { return &net.TCPAddr{} }

type mockConn struct {
	remoteAddr string
	closed     bool
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return 0, nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.ParseIP(m.remoteAddr)} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestHTBListener_Mocked(t *testing.T) {
	mListener := &mockListener{conns: make(chan net.Conn, 10)}
	l := LimitListener(mListener, 1, 1)

	// Accept normal
	mConn1 := &mockConn{remoteAddr: "192.168.1.1"}
	mListener.conns <- mConn1
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Fatal("expected connection")
	}

	// Accept blocked due to rate limit (same IP)
	mConn2 := &mockConn{remoteAddr: "192.168.1.1"}
	mConn3 := &mockConn{remoteAddr: "192.168.1.2"} // Will be allowed
	mListener.conns <- mConn2
	mListener.conns <- mConn3

	conn, err = l.Accept()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mConn2.closed != true {
		t.Errorf("expected connection 2 to be closed")
	}
	// It should eventually return mConn3
	if conn.(*mockConn) != mConn3 {
		t.Errorf("expected to return mConn3")
	}
}

func TestHTBListener_NoLimit(t *testing.T) {
	mListener := &mockListener{conns: make(chan net.Conn, 10)}
	l := LimitListener(mListener, 0, 0)
	if l != mListener {
		t.Errorf("expected no wrapper for limit <= 0")
	}
}

func TestMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mw := Middleware(1, 1, handler)

	// Request 1: allowed
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	w1 := httptest.NewRecorder()
	mw.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w1.Code)
	}

	// Request 2: blocked (same IP)
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "10.0.0.1:1235"
	w2 := httptest.NewRecorder()
	mw.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", w2.Code)
	}

	// Request 3: allowed (different IP)
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "10.0.0.2:1234"
	w3 := httptest.NewRecorder()
	mw.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w3.Code)
	}
}

func TestMiddleware_NoLimit(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	mw := Middleware(0, 0, handler)
	
	// Ensure we get the same handler back
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestHTBListener_Error(t *testing.T) {
	mListener := &mockListener{err: fmt.Errorf("accept error")}
	l := LimitListener(mListener, 1, 1)

	_, err := l.Accept()
	if err == nil || err.Error() != "accept error" {
		t.Errorf("expected accept error, got %v", err)
	}
}
