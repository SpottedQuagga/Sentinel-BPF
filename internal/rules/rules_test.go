package rules

import (
	"testing"
	"time"

	"github.com/sentinel-bpf/sentinel/internal/config"
	"github.com/sentinel-bpf/sentinel/internal/container"
	"github.com/sentinel-bpf/sentinel/internal/events"
	"github.com/sentinel-bpf/sentinel/internal/proctable"
)

func TestReverseShellRule(t *testing.T) {
	shells := []string{"/bin/sh", "/bin/bash"}

	tests := []struct {
		name          string
		treatLoopback bool
		eventSequence []*events.Event
		expectAlert   bool
	}{
		{
			name:          "Positive: connect external -> dup stdin -> exec sh",
			treatLoopback: false,
			eventSequence: []*events.Event{
				{
					EventType: events.EventConnect,
					Pid:       101,
					Fd:        4,
					Daddr:     "198.51.100.1",
					Dport:     4444,
				},
				{
					EventType: events.EventDup,
					Pid:       101,
					OldFd:     4,
					NewFd:     0, // stdin
				},
				{
					EventType: events.EventExec,
					Pid:       101,
					Path:      "/bin/sh",
					Comm:      "sh",
				},
			},
			expectAlert: true,
		},
		{
			name:          "Benign look-alike: connect external -> exec /bin/ls without dup",
			treatLoopback: false,
			eventSequence: []*events.Event{
				{
					EventType: events.EventConnect,
					Pid:       102,
					Fd:        4,
					Daddr:     "198.51.100.1",
					Dport:     443,
				},
				{
					EventType: events.EventExec,
					Pid:       102,
					Path:      "/bin/ls",
					Comm:      "ls",
				},
			},
			expectAlert: false,
		},
		{
			name:          "Benign look-alike: connect external -> exec /bin/sh without dup (connect + exec only does not alert)",
			treatLoopback: false,
			eventSequence: []*events.Event{
				{
					EventType: events.EventConnect,
					Pid:       109,
					Fd:        4,
					Daddr:     "198.51.100.1",
					Dport:     443,
				},
				{
					EventType: events.EventExec,
					Pid:       109,
					Path:      "/bin/sh",
					Comm:      "sh",
				},
			},
			expectAlert: false,
		},
		{
			name:          "Benign look-alike: dup stdin -> exec sh without prior connect",
			treatLoopback: false,
			eventSequence: []*events.Event{
				{
					EventType: events.EventDup,
					Pid:       103,
					OldFd:     4,
					NewFd:     0,
				},
				{
					EventType: events.EventExec,
					Pid:       103,
					Path:      "/bin/sh",
					Comm:      "sh",
				},
			},
			expectAlert: false,
		},
		{
			name:          "Loopback ignored when treatLoopback is false",
			treatLoopback: false,
			eventSequence: []*events.Event{
				{
					EventType: events.EventConnect,
					Pid:       104,
					Fd:        4,
					Daddr:     "127.0.0.1",
					Dport:     4444,
				},
				{
					EventType: events.EventDup,
					Pid:       104,
					OldFd:     4,
					NewFd:     0,
				},
				{
					EventType: events.EventExec,
					Pid:       104,
					Path:      "/bin/sh",
					Comm:      "sh",
				},
			},
			expectAlert: false,
		},
		{
			name:          "Loopback alerted when treatLoopback is true",
			treatLoopback: true,
			eventSequence: []*events.Event{
				{
					EventType: events.EventConnect,
					Pid:       105,
					Fd:        5,
					Daddr:     "127.0.0.1",
					Dport:     4444,
				},
				{
					EventType: events.EventDup,
					Pid:       105,
					OldFd:     5,
					NewFd:     1, // stdout
				},
				{
					EventType: events.EventExec,
					Pid:       105,
					Path:      "/bin/bash",
					Comm:      "bash",
				},
			},
			expectAlert: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := NewReverseShellRule(tt.treatLoopback, shells)
			var gotAlerts []Alert

			for _, ev := range tt.eventSequence {
				alerts := rule.Handle(ev, nil)
				gotAlerts = append(gotAlerts, alerts...)
			}

			if tt.expectAlert && len(gotAlerts) == 0 {
				t.Fatalf("expected alert but got none")
			}
			if !tt.expectAlert && len(gotAlerts) > 0 {
				t.Fatalf("did not expect alert but got %d alerts", len(gotAlerts))
			}
		})
	}
}

func TestPrivilegeEscalationRule(t *testing.T) {
	rule := NewPrivilegeEscalationRule()

	tests := []struct {
		name        string
		event       *events.Event
		expectAlert bool
		severity    Severity
	}{
		{
			name: "Positive: setuid(0) by non-root (euid 1000)",
			event: &events.Event{
				EventType: events.EventSetUID,
				Pid:       201,
				Uid:       1000,
				Euid:      1000,
				Retval:    0, // Target UID 0
				Comm:      "exploit",
			},
			expectAlert: true,
			severity:    SeverityHigh,
		},
		{
			name: "Benign look-alike: setuid(0) by root (euid 0)",
			event: &events.Event{
				EventType: events.EventSetUID,
				Pid:       202,
				Uid:       0,
				Euid:      0,
				Retval:    0,
				Comm:      "systemd",
			},
			expectAlert: false,
		},
		{
			name: "Positive: non-root user executes sudo",
			event: &events.Event{
				EventType: events.EventExec,
				Pid:       203,
				Uid:       1000,
				Euid:      1000,
				Path:      "/usr/bin/sudo",
				Comm:      "sudo",
			},
			expectAlert: true,
			severity:    SeverityMedium,
		},
		{
			name: "Benign look-alike: non-root user executes normal binary (ls)",
			event: &events.Event{
				EventType: events.EventExec,
				Pid:       204,
				Uid:       1000,
				Euid:      1000,
				Path:      "/bin/ls",
				Comm:      "ls",
			},
			expectAlert: false,
		},
		{
			name: "Benign look-alike: setuid binary (passwd) executed with euid 0 must not alert",
			event: &events.Event{
				EventType: events.EventExec,
				Pid:       205,
				Uid:       1000,
				Euid:      0, // Legitimate setuid execution
				Path:      "/usr/bin/passwd",
				Comm:      "passwd",
			},
			expectAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts := rule.Handle(tt.event, nil)
			if tt.expectAlert {
				if len(alerts) == 0 {
					t.Fatalf("expected alert but got none")
				}
				if alerts[0].Severity != tt.severity {
					t.Errorf("expected severity %v, got %v", tt.severity, alerts[0].Severity)
				}
			} else {
				if len(alerts) > 0 {
					t.Fatalf("did not expect alert but got: %v", alerts)
				}
			}
		})
	}
}

func TestFileTamperingRule(t *testing.T) {
	rule := NewFileTamperingRule(
		[]string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/pam.d"},
		[]string{"/usr/bin/passwd", "/usr/sbin/useradd"},
	)

	pt := proctable.New(10)
	// Register legitimate passwd binary in proctable
	pt.Put(&proctable.ProcessInfo{
		Pid:  304,
		Comm: "passwd",
		Path: "/usr/bin/passwd",
	})
	state := &State{ProcTable: pt}

	tests := []struct {
		name        string
		event       *events.Event
		expectAlert bool
	}{
		{
			name: "Positive: malicious write open to /etc/shadow",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       301,
				Comm:      "backdoor",
				Path:      "/etc/shadow",
				Flags:     0x2, // O_RDWR
			},
			expectAlert: true,
		},
		{
			name: "Positive: write open to file inside sensitive directory (/etc/pam.d/sshd)",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       305,
				Comm:      "backdoor",
				Path:      "/etc/pam.d/sshd",
				Flags:     0x2,
			},
			expectAlert: true,
		},
		{
			name: "Benign look-alike: write open to prefix lookalike (/etc/pam.dx) must not alert",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       306,
				Comm:      "backdoor",
				Path:      "/etc/pam.dx",
				Flags:     0x2,
			},
			expectAlert: false,
		},
		{
			name: "Positive: path traversal normalization (/etc/../etc/shadow) alerts",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       307,
				Comm:      "backdoor",
				Path:      "/etc/../etc/shadow",
				Flags:     0x2,
			},
			expectAlert: true,
		},
		{
			name: "Allowlisted case: write to /etc/passwd by legitimate passwd binary via comm",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       302,
				Comm:      "passwd",
				Path:      "/etc/passwd",
				Flags:     0x2,
			},
			expectAlert: false,
		},
		{
			name: "Allowlisted case: write to /etc/passwd verified via process table exe path",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       304,
				Comm:      "passwd",
				Path:      "/etc/passwd",
				Flags:     0x2,
			},
			expectAlert: false,
		},
		{
			name: "Benign look-alike: write open to harmless file (/tmp/foo)",
			event: &events.Event{
				EventType: events.EventOpenAt,
				Pid:       303,
				Comm:      "app",
				Path:      "/tmp/foo",
				Flags:     0x2,
			},
			expectAlert: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts := rule.Handle(tt.event, state)
			if tt.expectAlert && len(alerts) == 0 {
				t.Fatalf("expected alert for %s", tt.name)
			}
			if !tt.expectAlert && len(alerts) > 0 {
				t.Fatalf("unexpected alert for %s: %v", tt.name, alerts)
			}
		})
	}
}

func TestUnauthorizedMountRule(t *testing.T) {
	rule := NewUnauthorizedMountRule()
	ct := container.New(10)
	state := &State{Container: ct}

	// 1. Positive: Mount inside container -> SeverityHigh
	ct.Resolve(100, 701) // Cache container resolution if needed
	// Simulate container tracker having cgroup ID 100 resolved to a container
	containerEvent := &events.Event{
		EventType:   events.EventMount,
		Pid:         701,
		CgroupID:    100,
		ContainerID: "docker-12345",
		Path:        "/mnt/host",
		Extra:       "/dev/sda1",
		Comm:        "mount",
	}
	alerts := rule.Handle(containerEvent, state)
	if len(alerts) == 0 {
		t.Fatal("expected alert for container mount")
	}
	if alerts[0].Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh for container mount, got %v", alerts[0].Severity)
	}

	// 2. Benign/Host: Mount outside container -> SeverityMedium
	hostEvent := &events.Event{
		EventType: events.EventMount,
		Pid:       702,
		Path:      "/mnt/usb",
		Extra:     "/dev/sdb1",
		Comm:      "mount",
	}
	hostAlerts := rule.Handle(hostEvent, state)
	if len(hostAlerts) == 0 {
		t.Fatal("expected alert for host mount")
	}
	if hostAlerts[0].Severity != SeverityMedium {
		t.Errorf("expected SeverityMedium for host mount, got %v", hostAlerts[0].Severity)
	}

	// 3. Non-mount event -> No alert
	nonMountEvent := &events.Event{
		EventType: events.EventOpenAt,
		Pid:       703,
		Path:      "/mnt/usb",
		Comm:      "ls",
	}
	if len(rule.Handle(nonMountEvent, state)) > 0 {
		t.Fatal("expected no alert for non-mount event")
	}
}

func TestProcessInjectionRule(t *testing.T) {
	rule := NewProcessInjectionRule()

	// Positive case: rogue process ptrace against target PID
	posAlerts := rule.Handle(&events.Event{
		EventType: events.EventPtrace,
		Pid:       401,
		NewFd:     402, // target pid
		Comm:      "injector",
	}, nil)

	if len(posAlerts) == 0 {
		t.Fatal("expected alert for ptrace injection")
	}

	// Allowlisted debugger (gdb)
	benignAlerts := rule.Handle(&events.Event{
		EventType: events.EventPtrace,
		Pid:       403,
		NewFd:     404,
		Comm:      "gdb",
	}, nil)

	if len(benignAlerts) > 0 {
		t.Fatal("expected no alert for allowlisted debugger gdb")
	}
}

func TestAlertDeduplication(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Rules.AlertCooldownSeconds = 5
	pt := proctable.New(10)
	ct := container.New(10)

	engine := NewEngine(cfg, pt, ct)

	// Tampering event
	ev := &events.Event{
		EventType: events.EventOpenAt,
		Pid:       501,
		Comm:      "malware",
		Path:      "/etc/shadow",
		Flags:     2,
	}

	// First evaluation emits alert
	alerts1 := engine.Evaluate(ev)
	if len(alerts1) == 0 {
		t.Fatal("expected alert on first evaluation")
	}

	// Immediate repeat of identical event within cooldown must be suppressed
	alerts2 := engine.Evaluate(ev)
	if len(alerts2) != 0 {
		t.Fatalf("expected deduplication to suppress duplicate alert, got %d alerts", len(alerts2))
	}

	// Check recent alerts history contains the first alert
	hist := engine.RecentAlerts(10)
	if len(hist) != 1 {
		t.Errorf("expected history length 1, got %d", len(hist))
	}

	// Fast-forward cooldown by updating map entry
	engine.mu.Lock()
	engine.cooldowns["file_tampering:501:/etc/shadow"] = time.Now().Add(-10 * time.Second)
	engine.mu.Unlock()

	// After cooldown expired, alert is emitted again
	alerts3 := engine.Evaluate(ev)
	if len(alerts3) == 0 {
		t.Fatal("expected alert after cooldown expired")
	}
}
