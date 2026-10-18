package proctable

import (
	"testing"

	"github.com/sentinel-bpf/sentinel/internal/events"
)

func TestProcessTableExecAndLineage(t *testing.T) {
	tbl := New(100)

	// Simulate system init: PID 1
	tbl.Put(&ProcessInfo{
		Pid:  1,
		Ppid: 0,
		Comm: "systemd",
		Path: "/usr/lib/systemd/systemd",
	})

	// Simulate sshd: PID 1000, parent 1
	tbl.Put(&ProcessInfo{
		Pid:  1000,
		Ppid: 1,
		Comm: "sshd",
		Path: "/usr/sbin/sshd",
	})

	// Simulate bash: PID 1200, parent 1000 via HandleExec
	execEv := &events.Event{
		EventType:   events.EventExec,
		Pid:         1200,
		Ppid:        1000,
		Comm:        "bash",
		Path:        "/bin/bash",
		TimestampNs: 1000,
	}
	tbl.HandleExec(execEv)

	// Query lineage for PID 1200
	lineage := tbl.GetLineage(1200)
	if len(lineage) != 3 {
		t.Fatalf("expected lineage length 3 (1200 -> 1000 -> 1), got %d", len(lineage))
	}

	if lineage[0].Pid != 1200 || lineage[1].Pid != 1000 || lineage[2].Pid != 1 {
		t.Errorf("unexpected lineage chain: [%d, %d, %d]", lineage[0].Pid, lineage[1].Pid, lineage[2].Pid)
	}
}

func TestProcessTableBounding(t *testing.T) {
	// Table with max 5 processes
	tbl := New(5)

	for i := uint32(1); i <= 10; i++ {
		tbl.Put(&ProcessInfo{
			Pid:  i,
			Ppid: 1,
			Comm: "test",
		})
	}

	if tbl.Count() > 5 {
		t.Errorf("expected table count <= 5, got %d", tbl.Count())
	}
}

func TestLineageCyclePrevention(t *testing.T) {
	tbl := New(10)

	// Create artificial cycle: 10 -> 20 -> 10
	tbl.Put(&ProcessInfo{Pid: 10, Ppid: 20})
	tbl.Put(&ProcessInfo{Pid: 20, Ppid: 10})

	lineage := tbl.GetLineage(10)
	// Must terminate cleanly without hanging or exceeding 32
	if len(lineage) > 2 {
		t.Errorf("cycle not prevented: lineage length %d", len(lineage))
	}
}

func TestHandleForkAndExit(t *testing.T) {
	tbl := New(10)
	tbl.Put(&ProcessInfo{
		Pid:  500,
		Comm: "parent_worker",
		Path: "/usr/bin/worker",
	})

	forkEv := &events.Event{
		EventType: events.EventFork,
		Pid:       500,
		NewFd:     501, // Child PID
		Comm:      "parent_worker",
	}
	tbl.HandleFork(forkEv)

	child, found := tbl.Get(501)
	if !found {
		t.Fatal("child process 501 not found after fork")
	}
	if child.Ppid != 500 {
		t.Errorf("expected child PPID 500, got %d", child.Ppid)
	}
	if child.Comm != "parent_worker" {
		t.Errorf("expected child Comm parent_worker, got %s", child.Comm)
	}

	// Exit
	exitEv := &events.Event{
		EventType: events.EventExit,
		Pid:       501,
	}
	tbl.HandleExit(exitEv)

	childAfterExit, _ := tbl.Get(501)
	if !childAfterExit.Exited {
		t.Error("expected child to be marked exited")
	}
}

func TestProcessReparentingOnExit(t *testing.T) {
	tbl := New(20)

	// Parent process: PID 600
	tbl.Put(&ProcessInfo{
		Pid:  600,
		Ppid: 1,
		Comm: "parent_app",
	})

	// Child process: PID 601, parent 600
	tbl.Put(&ProcessInfo{
		Pid:  601,
		Ppid: 600,
		Comm: "child_worker",
	})

	// Parent terminates
	tbl.HandleExit(&events.Event{
		EventType: events.EventExit,
		Pid:       600,
	})

	// Verify child 601 is now reparented to PID 1
	child, ok := tbl.Get(601)
	if !ok {
		t.Fatal("child process not found")
	}
	if child.Ppid != 1 {
		t.Errorf("expected child to be reparented to PPID 1, got %d", child.Ppid)
	}
}
