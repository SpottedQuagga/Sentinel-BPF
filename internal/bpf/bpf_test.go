package bpf

import (
	"context"
	"testing"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

func TestMockReaderSeedLineage(t *testing.T) {
	mr := NewMockReader()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	out := make(chan *events.Event, 100)
	if err := mr.Start(ctx, out); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Collect seed events (first 4 should be init, sshd, bash, python3)
	var seeds []*events.Event
timeout:
	for i := 0; i < 4; i++ {
		select {
		case ev := <-out:
			seeds = append(seeds, ev)
		case <-time.After(200 * time.Millisecond):
			break timeout
		}
	}

	if len(seeds) < 4 {
		t.Fatalf("expected at least 4 seed events, got %d", len(seeds))
	}

	// init(1) -> ppid 0
	if seeds[0].Pid != 1 || seeds[0].Ppid != 0 {
		t.Errorf("init: pid=%d ppid=%d, want pid=1 ppid=0", seeds[0].Pid, seeds[0].Ppid)
	}
	// sshd(100) -> ppid 1
	if seeds[1].Pid != 100 || seeds[1].Ppid != 1 {
		t.Errorf("sshd: pid=%d ppid=%d, want pid=100 ppid=1", seeds[1].Pid, seeds[1].Ppid)
	}
	// bash(200) -> ppid 100
	if seeds[2].Pid != 200 || seeds[2].Ppid != 100 {
		t.Errorf("bash: pid=%d ppid=%d, want pid=200 ppid=100", seeds[2].Pid, seeds[2].Ppid)
	}
	// python3(300) -> ppid 200
	if seeds[3].Pid != 300 || seeds[3].Ppid != 200 {
		t.Errorf("python3: pid=%d ppid=%d, want pid=300 ppid=200", seeds[3].Pid, seeds[3].Ppid)
	}

	// Verify comm values
	expectedComms := []string{"systemd", "sshd", "bash", "python3"}
	for i, ev := range seeds {
		if ev.Comm != expectedComms[i] {
			t.Errorf("seed[%d]: comm=%q, want %q", i, ev.Comm, expectedComms[i])
		}
	}

	// No seed event should have Ppid 1000 (the old hardcoded value)
	for _, ev := range seeds {
		if ev.Ppid == 1000 {
			t.Errorf("seed event pid=%d has hardcoded Ppid:1000", ev.Pid)
		}
	}
}

func TestMockReaderWorkerLineage(t *testing.T) {
	mr := NewMockReader()
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	out := make(chan *events.Event, 200)
	if err := mr.Start(ctx, out); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Collect events and look for worker fork/exec pairs
	workerCount := 0
	for i := 0; i < 30; i++ {
		select {
		case ev := <-out:
			if ev.EventType == events.EventFork && ev.Pid == 300 {
				// Fork event: parent is python3(300), child PID in NewFd
				if ev.Ppid != 200 {
					t.Errorf("fork event: pid=%d ppid=%d, want ppid=200 (bash)", ev.Pid, ev.Ppid)
				}
				workerCount++
			}
			if ev.EventType == events.EventExec && ev.Pid >= 400 && ev.Pid < 410 {
				// Worker exec: parent should be python3(300)
				if ev.Ppid != 300 {
					t.Errorf("worker exec: pid=%d ppid=%d, want ppid=300 (python3)", ev.Pid, ev.Ppid)
				}
				if ev.Ppid == 1000 {
					t.Errorf("worker exec pid=%d has hardcoded Ppid:1000", ev.Pid)
				}
			}
		case <-time.After(200 * time.Millisecond):
		}
	}

	if workerCount == 0 {
		t.Error("no worker fork events observed")
	}
}

func TestMockReaderAttackChain(t *testing.T) {
	mr := NewMockReader()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan *events.Event, 200)
	if err := mr.Start(ctx, out); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for a reverse shell chain (seq%25 == 0, roughly 8.75 seconds)
	var connectEv, dupEv, execEv *events.Event
	timeout := time.After(12 * time.Second)
readloop:
	for {
		select {
		case ev := <-out:
			if ev.EventType == events.EventConnect && ev.Daddr == "198.51.100.42" {
				connectEv = ev
			}
			if ev.EventType == events.EventDup && ev.OldFd == 4 && ev.NewFd == 0 {
				dupEv = ev
			}
			if ev.EventType == events.EventExec && ev.Path == "/bin/sh" && ev.Comm == "sh" {
				execEv = ev
			}
			if connectEv != nil && dupEv != nil && execEv != nil {
				break readloop
			}
		case <-timeout:
			break readloop
		}
	}

	if connectEv == nil {
		t.Fatal("no reverse shell connect event observed")
	}
	if connectEv.Ppid != 200 {
		t.Errorf("connect: pid=%d ppid=%d, want ppid=200 (bash)", connectEv.Pid, connectEv.Ppid)
	}
	if connectEv.Ppid == 1000 {
		t.Error("connect event has hardcoded Ppid:1000")
	}

	if dupEv == nil {
		t.Fatal("no reverse shell dup event observed")
	}
	if dupEv.Ppid != 200 {
		t.Errorf("dup: pid=%d ppid=%d, want ppid=200 (bash)", dupEv.Pid, dupEv.Ppid)
	}

	if execEv == nil {
		t.Fatal("no reverse shell exec event observed")
	}
	if execEv.Ppid != 200 {
		t.Errorf("exec: pid=%d ppid=%d, want ppid=200 (bash)", execEv.Pid, execEv.Ppid)
	}

	// All three events should share the same PID (nc -> sh)
	if connectEv.Pid != dupEv.Pid || dupEv.Pid != execEv.Pid {
		t.Errorf("attack chain PIDs mismatch: connect=%d dup=%d exec=%d",
			connectEv.Pid, dupEv.Pid, execEv.Pid)
	}
}

func TestMockReaderFileTampering(t *testing.T) {
	mr := NewMockReader()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	out := make(chan *events.Event, 200)
	if err := mr.Start(ctx, out); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for file tampering event (seq%40 == 0, roughly 14 seconds)
	var openEv *events.Event
	timeout := time.After(17 * time.Second)
readloop:
	for {
		select {
		case ev := <-out:
			if ev.EventType == events.EventOpenAt && ev.Path == "/etc/shadow" {
				openEv = ev
				break readloop
			}
		case <-timeout:
			break readloop
		}
	}

	if openEv == nil {
		t.Fatal("no file tampering openat event observed")
	}
	if openEv.Ppid != 200 {
		t.Errorf("openat: pid=%d ppid=%d, want ppid=200 (bash)", openEv.Pid, openEv.Ppid)
	}
	if openEv.Ppid == 1000 {
		t.Error("openat event has hardcoded Ppid:1000")
	}
}

func TestMockReaderNoHardcodedPpid1000(t *testing.T) {
	mr := NewMockReader()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out := make(chan *events.Event, 200)
	if err := mr.Start(ctx, out); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	count := 0
	for i := 0; i < 50; i++ {
		select {
		case ev := <-out:
			count++
			if ev.Ppid == 1000 {
				t.Errorf("event type=%s pid=%d has hardcoded Ppid:1000", ev.TypeName, ev.Pid)
			}
		case <-time.After(100 * time.Millisecond):
		}
	}

	if count == 0 {
		t.Error("no events observed from MockReader")
	}
}
