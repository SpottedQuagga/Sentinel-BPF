package api

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/hub"
	"github.com/sentinel-bpf/sentinel/internal/proctable"
	"github.com/sentinel-bpf/sentinel/internal/rules"
)

// Server provides the HTTP REST API and WebSocket endpoints for SentinelBPF.
type Server struct {
	cfg       *config.Config
	hub       *hub.Hub
	rules     *rules.Engine
	procs     *proctable.Table
	startTime time.Time
	upgrader  websocket.Upgrader

	// Counters
	eventCount  uint64
	kernelDrops uint64
	mock        bool
}

// NewServer initializes a new API server.
func NewServer(cfg *config.Config, h *hub.Hub, re *rules.Engine, pt *proctable.Table) *Server {
	s := &Server{
		cfg:       cfg,
		hub:       h,
		rules:     re,
		procs:     pt,
		startTime: time.Now(),
	}

	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin:     s.checkOrigin,
	}

	return s
}

// Handler returns the configured HTTP ServeMux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/api/v1/health", s.handleHealth)
	mux.HandleFunc("/api/v1/status", s.authMiddleware(s.handleStatus))
	mux.HandleFunc("/api/v1/alerts", s.authMiddleware(s.handleAlerts))
	mux.HandleFunc("/api/v1/processes", s.authMiddleware(s.handleProcesses))
	mux.HandleFunc("/api/v1/process/", s.authMiddleware(s.handleProcessDetail))
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/api/v1/ws", s.handleWebSocket)

	return s.corsMiddleware(mux)
}

func (s *Server) SetTelemetry(eventCount, kernelDrops uint64) {
	s.eventCount = eventCount
	s.kernelDrops = kernelDrops
}

func (s *Server) SetMock(mock bool) {
	s.mock = mock
}

func (s *Server) checkOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Allow non-browser requests
	}

	u, err := url.Parse(origin)
	if err != nil {
		return false
	}

	// Always allow localhost
	if u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" {
		return true
	}

	for _, allowed := range s.cfg.Server.AllowedOrigins {
		if strings.EqualFold(origin, allowed) {
			return true
		}
	}
	return false
}

func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.Server.AuthToken != "" {
			token := r.Header.Get("Authorization")
			if strings.HasPrefix(token, "Bearer ") {
				token = strings.TrimPrefix(token, "Bearer ")
			} else {
				token = r.URL.Query().Get("token")
			}

			if token != s.cfg.Server.AuthToken {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
		}
		next(w, r)
	}
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"uptime_seconds":   int(time.Since(s.startTime).Seconds()),
		"events_processed": s.eventCount,
		"kernel_drops":     s.kernelDrops,
		"active_processes": s.procs.Count(),
		"active_clients":   s.hub.ClientCount(),
		"mock":             s.mock,
	})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	w.Header().Set("Content-Type", "application/json")
	alerts := s.rules.RecentAlerts(limit)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count":  len(alerts),
		"alerts": alerts,
	})
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	procs := s.procs.GetAll()
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"count":     len(procs),
		"processes": procs,
	})
}

func (s *Server) handleProcessDetail(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, `{"error":"missing pid"}`, http.StatusBadRequest)
		return
	}

	pid, err := strconv.Atoi(parts[4])
	if err != nil {
		http.Error(w, `{"error":"invalid pid"}`, http.StatusBadRequest)
		return
	}

	info, exists := s.procs.Get(uint32(pid))
	if !exists {
		http.Error(w, `{"error":"process not found"}`, http.StatusNotFound)
		return
	}

	lineage := s.procs.GetLineage(uint32(pid))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"process": info,
		"lineage": lineage,
	})
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Verify auth token if enabled
	if s.cfg.Server.AuthToken != "" {
		token := r.URL.Query().Get("token")
		if token == "" {
			token = r.Header.Get("Authorization")
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token != s.cfg.Server.AuthToken {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := s.hub.RegisterClient(conn)

	// Send hello greeting with mock simulation indicator
	helloMsg := map[string]interface{}{
		"type":    "hello",
		"mock":    s.mock,
		"version": "1.0.0",
	}
	if b, err := json.Marshal(helloMsg); err == nil {
		client.Send(b)
	}

	// Send initial state & snapshot to newly connected client
	recentAlerts := s.rules.RecentAlerts(50)
	snapshotMsg := map[string]interface{}{
		"type": "snapshot",
		"data": map[string]interface{}{
			"alerts":           recentAlerts,
			"active_processes": s.procs.Count(),
			"uptime_seconds":   int(time.Since(s.startTime).Seconds()),
			"mock":             s.mock,
		},
	}
	if b, err := json.Marshal(snapshotMsg); err == nil {
		client.Send(b)
	}

	initialState := map[string]interface{}{
		"type": "initial_state",
		"data": map[string]interface{}{
			"alerts":           recentAlerts,
			"active_processes": s.procs.Count(),
			"uptime_seconds":   int(time.Since(s.startTime).Seconds()),
			"mock":             s.mock,
		},
	}
	if initBytes, err := json.Marshal(initialState); err == nil {
		client.Send(initBytes)
	}
}
