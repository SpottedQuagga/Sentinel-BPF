package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/api"
	"github.com/sentinel-bpf/sentinel/internal/bpf"
	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/container"
	"github.com/sentinel-bpf/sentinel/internal/events"
	"github.com/sentinel-bpf/sentinel/internal/hub"
	"github.com/sentinel-bpf/sentinel/internal/proctable"
	"github.com/sentinel-bpf/sentinel/internal/rules"
)

const AppVersion = "1.0.0"

func main() {
	configPath := flag.String("config", "config.yaml", "Path to YAML configuration file")
	mockMode := flag.Bool("mock", false, "Run in synthetic simulation mode (no root/eBPF required)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SentinelBPF version %s (%s/%s)\n", AppVersion, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	log.Printf("[SentinelBPF] Starting daemon version %s (PID: %d)", AppVersion, os.Getpid())

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Printf("[WARN] Failed to load config from %s: %v. Using defaults.", *configPath, err)
		cfg = config.DefaultConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize components
	procTable := proctable.New(10000)
	containerTracker := container.New(4096)
	ruleEngine := rules.NewEngine(cfg, procTable, containerTracker)
	wsHub := hub.New()
	apiServer := api.NewServer(cfg, wsHub, ruleEngine, procTable)

	// Start WebSocket hub
	go wsHub.Run()

	// Event queue between reader and processors
	eventQueue := make(chan *events.Event, cfg.BPF.EventBufferSize)

	// Determine BPF reader mode
	var reader bpf.Reader
	var bpfSession *bpf.LinuxBPFSession

	if *mockMode || runtime.GOOS != "linux" {
		log.Println("[INFO] Running in synthetic simulation mode (MockReader).")
		reader = bpf.NewMockReader()
		apiServer.SetMock(true)
	} else {
		log.Println("[INFO] Initializing eBPF subsystem...")
		// On real Linux system, eBPF attachments are established
		// Fallback to mock reader if not running as root
		if os.Geteuid() != 0 {
			log.Println("[WARN] Daemon not running as root (euid != 0). Falling back to mock simulation mode.")
			reader = bpf.NewMockReader()
			apiServer.SetMock(true)
		} else {
			session, err := bpf.LoadAndAttach(cfg)
			if err != nil {
				log.Fatalf("[FATAL] eBPF initialization failed: %v", err)
			}
			bpfSession = session
			reader = session.Reader
			log.Println("[INFO] Attached eBPF programs and opened ring buffer reader.")
			apiServer.SetMock(false)
		}
	}

	// Start event consumer worker pool
	var totalEvents uint64
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-eventQueue:
				if !ok {
					return
				}
				atomic.AddUint64(&totalEvents, 1)

				// Update process table
				switch ev.EventType {
				case events.EventExec:
					procTable.HandleExec(ev)
				case events.EventFork:
					procTable.HandleFork(ev)
				case events.EventExit:
					procTable.HandleExit(ev)
				}

				// Resolve container ID
				if ev.ContainerID == "" && ev.CgroupID > 0 {
					ev.ContainerID = containerTracker.Resolve(ev.CgroupID, ev.Pid)
				}

				// Evaluate rules & alerts
				alerts := ruleEngine.Evaluate(ev)

				// Broadcast event to WebSocket clients (droppable under backpressure)
				wsHub.BroadcastEvent(ev)

				// Broadcast alerts (high priority, never dropped before events)
				for i := range alerts {
					wsHub.BroadcastAlert(&alerts[i])
					log.Printf("[ALERT] [%s] %s (PID: %d, Comm: %s)", alerts[i].Severity, alerts[i].Message, alerts[i].Pid, alerts[i].Comm)
				}
			}
		}
	}()

	// Start reader
	if err := reader.Start(ctx, eventQueue); err != nil {
		log.Fatalf("[FATAL] Failed to start event reader: %v", err)
	}

	// Periodic telemetry ticker (1 Hz)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		var lastEvents uint64
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				currEvents := atomic.LoadUint64(&totalEvents)
				eps := currEvents - lastEvents
				lastEvents = currEvents

				drops := reader.KernelDrops()
				if bpfSession != nil {
					drops += bpfSession.ReadKernelDrops()
				}
				apiServer.SetTelemetry(currEvents, drops)

				telemetry := map[string]interface{}{
					"events_per_sec":   eps,
					"total_events":     currEvents,
					"kernel_drops":     drops,
					"active_processes": procTable.Count(),
					"active_clients":   wsHub.ClientCount(),
				}
				wsHub.BroadcastMetrics(telemetry)
			}
		}
	}()

	// Start HTTP/WebSocket server
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	httpServer := &http.Server{
		Addr:         serverAddr,
		Handler:      apiServer.Handler(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("[INFO] SentinelBPF API & WebSocket server listening on http://%s", serverAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[FATAL] HTTP server failed: %v", err)
		}
	}()

	// Graceful shutdown handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	sig := <-sigCh
	log.Printf("[INFO] Received signal %v. Initiating graceful shutdown...", sig)

	// 1. Cancel root context to stop workers and readers
	cancel()

	// 2. Shut down HTTP server
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)

	// 3. Close reader, eBPF session, and channels
	_ = reader.Close()
	if bpfSession != nil {
		_ = bpfSession.Close()
	}
	close(eventQueue)

	// 4. Wait for worker goroutines to drain
	wg.Wait()

	log.Println("[INFO] SentinelBPF daemon stopped cleanly.")
}
