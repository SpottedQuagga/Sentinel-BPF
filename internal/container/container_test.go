package container

import (
	"testing"
)

func TestExtractContainerID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Docker cgroup line",
			input:    "12:memory:/docker/a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef",
			expected: "a1b2c3d4e5f6",
		},
		{
			name:     "Containerd systemd scope",
			input:    "0::/system.slice/containerd-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef.scope",
			expected: "1234567890ab",
		},
		{
			name:     "CRI-O cgroup",
			input:    "1:name=systemd:/kubepods.slice/crio-fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321.scope",
			expected: "fedcba098765",
		},
		{
			name:     "Host process non-container",
			input:    "0::/user.slice/user-1000.slice/session-2.scope",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractContainerID(tt.input)
			if got != tt.expected {
				t.Errorf("ExtractContainerID() = %q, expected %q", got, tt.expected)
			}
		})
	}
}

func TestTrackerCacheAndBounding(t *testing.T) {
	tracker := New(5)

	// Inject entries directly in cache for testing
	tracker.mu.Lock()
	for i := uint64(1); i <= 10; i++ {
		tracker.cache[i] = "cont-test"
	}
	tracker.mu.Unlock()

	// Resolve with non-zero cgroup
	res := tracker.Resolve(1, 0)
	if res != "cont-test" {
		t.Errorf("expected cached result 'cont-test', got %q", res)
	}

	// Zero cgroup returns empty string
	if zero := tracker.Resolve(0, 0); zero != "" {
		t.Errorf("expected empty string for cgroup 0, got %q", zero)
	}
}
