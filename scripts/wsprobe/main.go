package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

func main() {
	wsURL := flag.String("url", "ws://127.0.0.1:8080/ws", "WebSocket URL to connect to")
	token := flag.String("token", "", "Optional bearer token")
	duration := flag.Duration("duration", 10*time.Second, "Time to listen for messages")
	flag.Parse()

	targetURL, err := url.Parse(*wsURL)
	if err != nil {
		log.Fatalf("invalid url: %v", err)
	}
	if *token != "" {
		q := targetURL.Query()
		q.Set("token", *token)
		targetURL.RawQuery = q.Encode()
	}

	fmt.Printf("[WS PROBE] Connecting to %s ...\n", targetURL.String())
	conn, resp, err := websocket.DefaultDialer.Dial(targetURL.String(), nil)
	if err != nil {
		if resp != nil {
			log.Fatalf("failed to connect: %v (HTTP %d)", err, resp.StatusCode)
		}
		log.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()
	fmt.Println("[WS PROBE] Connected successfully.")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	timer := time.NewTimer(*duration)
	defer timer.Stop()

	seen := make(map[string]bool)
	type baseMsg struct {
		Type string `json:"type"`
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				return
			}
			var bm baseMsg
			if err := json.Unmarshal(message, &bm); err == nil && bm.Type != "" {
				fmt.Printf("[WS PROBE] Received message type: %s\n", bm.Type)
				if !seen[bm.Type] {
					seen[bm.Type] = true
					fmt.Printf("[WS PROBE] First %s message payload: %s\n", bm.Type, string(message))
				}
			}
		}
	}()

	select {
	case <-timer.C:
		fmt.Printf("[WS PROBE] %v listening duration completed. Total distinct message types: %d\n", *duration, len(seen))
	case <-sigCh:
		fmt.Println("[WS PROBE] Interrupted by user.")
	case <-done:
		fmt.Println("[WS PROBE] Server closed connection.")
	}

	_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "probe finished"))
	fmt.Println("[WS PROBE] Exiting cleanly.")
}
