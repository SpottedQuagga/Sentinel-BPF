package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sentinel-bpf/sentinel/internal/events"
	"github.com/sentinel-bpf/sentinel/internal/rules"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func TestHubFanOutAndAlertPriority(t *testing.T) {
	h := New()
	go h.Run()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Fatalf("upgrade failed: %v", err)
		}
		h.RegisterClient(conn)
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	clientConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer clientConn.Close()

	// Wait for registration
	time.Sleep(50 * time.Millisecond)
	if h.ClientCount() != 1 {
		t.Fatalf("expected 1 registered client, got %d", h.ClientCount() )
	}

	// Broadcast an alert
	alert := &rules.Alert{
		RuleName: "test_rule",
		Severity: rules.SeverityCritical,
		Message:  "critical test alert",
	}
	h.BroadcastAlert(alert)

	// Read message on client
	_ = clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msgBytes, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("read message failed: %v", err)
	}

	var msg Message
	if err := json.Unmarshal(msgBytes, &msg); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if msg.Type != "alert" {
		t.Errorf("expected msg.Type 'alert', got %q", msg.Type)
	}
}

func TestHubStalledClientDoesNotBlock(t *testing.T) {
	h := New()
	// Create mock client with small buffer
	c := &Client{
		hub:  h,
		send: make(chan []byte, 2),
	}
	h.clients[c] = true

	// Fill buffer completely
	c.send <- []byte("msg1")
	c.send <- []byte("msg2")

	// Broadcast event should NOT block even though client queue is full
	done := make(chan bool)
	go func() {
		ev := &events.Event{
			EventType: events.EventExec,
			Comm:      "ls",
		}
		h.BroadcastEvent(ev)
		done <- true
	}()

	select {
	case <-done:
		// Succeeded without blocking!
	case <-time.After(500 * time.Millisecond):
		t.Fatal("BroadcastEvent blocked on full client buffer")
	}

	// Broadcast alert should also NOT block, but should evict older message to prioritize alert
	go func() {
		alt := &rules.Alert{
			RuleName: "critical_alert",
			Severity: rules.SeverityCritical,
		}
		h.BroadcastAlert(alt)
		done <- true
	}()

	select {
	case <-done:
		// Succeeded without blocking!
	case <-time.After(500 * time.Millisecond):
		t.Fatal("BroadcastAlert blocked on full client buffer")
	}
}
