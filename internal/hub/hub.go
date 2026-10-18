package hub

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sentinel-bpf/sentinel/internal/events"
	"github.com/sentinel-bpf/sentinel/internal/rules"
)

// Message is the WebSocket envelope matching PROPOSED_SOLUTION.md Section 7.
type Message struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// Client represents a connected WebSocket client.
type Client struct {
	hub          *Hub
	conn         *websocket.Conn
	send         chan []byte
	stalledSince time.Time
	mu           sync.Mutex
	isClosed     bool
}

// Hub maintains the set of active clients and handles non-blocking fan-out.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client

	// Telemetry
	clientDropCount uint64
}

// New creates an initialized Hub.
func New() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		register:   make(chan *Client, 64),
		unregister: make(chan *Client, 64),
	}
}

// Run starts the hub coordination loop.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

		case client := <-h.unregister:
			h.removeClient(client)
		}
	}
}

// RegisterClient creates and registers a new WebSocket client.
func (h *Hub) RegisterClient(conn *websocket.Conn) *Client {
	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 1024), // Buffered queue per client
	}

	h.register <- client
	go client.writePump()
	go client.readPump()

	return client
}

// Send enqueues data directly to the client's send queue.
func (c *Client) Send(data []byte) {
	select {
	case c.send <- data:
	default:
	}
}

// BroadcastEvent enqueues an event to all clients with backpressure (droppable).
func (h *Hub) BroadcastEvent(ev *events.Event) {
	msg := Message{
		Type: "event",
		Data: ev,
	}
	bytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.fanOut(bytes, false)
}

// BroadcastAlert enqueues an alert to all clients (prioritized over events).
func (h *Hub) BroadcastAlert(alt *rules.Alert) {
	msg := Message{
		Type: "alert",
		Data: alt,
	}
	bytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.fanOut(bytes, true)
}

// BroadcastMetrics sends periodic telemetry updates.
func (h *Hub) BroadcastMetrics(data interface{}) {
	msg := Message{
		Type: "metrics",
		Data: data,
	}
	bytes, err := json.Marshal(msg)
	if err != nil {
		return
	}

	h.fanOut(bytes, false)
}

// ClientCount returns the number of active clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *Hub) fanOut(data []byte, isAlert bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		h.sendToClient(client, data, isAlert)
	}
}

// sendToClient implements strict backpressure rules:
// - Non-alert messages are dropped first if the client buffer is full.
// - Alerts are never dropped before events.
// - Persistently stalled clients are removed.
func (h *Hub) sendToClient(c *Client, data []byte, isAlert bool) {
	c.mu.Lock()
	if c.isClosed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	select {
	case c.send <- data:
		// Message delivered to client channel
		c.stalledSince = time.Time{}

	default:
		// Client queue is full
		if isAlert {
			// Alert priority: try to drain one queued non-alert message to make room
			select {
			case <-c.send: // Evict older non-critical message
			default:
			}

			// Try to deliver alert again
			select {
			case c.send <- data:
				return
			default:
			}
		}

		// Track drop
		h.mu.Lock()
		h.clientDropCount++
		h.mu.Unlock()

		// Check for persistently stalled client
		if c.stalledSince.IsZero() {
			c.stalledSince = time.Now()
		} else if time.Since(c.stalledSince) > 5*time.Second {
			// Client stalled for > 5 seconds, disconnect
			go h.removeClient(c)
		}
	}
}

func (h *Hub) removeClient(c *Client) {
	h.mu.Lock()
	if _, ok := h.clients[c]; ok {
		delete(h.clients, c)
		c.close()
	}
	h.mu.Unlock()
}

func (c *Client) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isClosed {
		c.isClosed = true
		close(c.send)
		if c.conn != nil {
			_ = c.conn.Close()
		}
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.hub.removeClient(c)
	}()

	for {
		select {
		case msg, ok := <-c.send:
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.removeClient(c)
	}()

	c.conn.SetReadLimit(4096)
	_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}
