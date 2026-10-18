package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// Container ID regex patterns for common runtimes (docker, containerd, cri-o, k8s)
var (
	dockerRegex     = regexp.MustCompile(`docker[-/]([a-f0-9]{64})`)
	containerdRegex = regexp.MustCompile(`containerd[-/]([a-f0-9]{64})`)
	crioRegex       = regexp.MustCompile(`crio[-/]([a-f0-9]{64})`)
	genericHexRegex = regexp.MustCompile(`[0-9a-f]{64}`)
)

// Tracker provides resolution from cgroup ID or process cgroup path to container ID.
type Tracker struct {
	mu         sync.RWMutex
	cache      map[uint64]string
	maxEntries int
}

// New creates an initialized Container Tracker with bounded cache.
func New(maxEntries int) *Tracker {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &Tracker{
		cache:      make(map[uint64]string, 256),
		maxEntries: maxEntries,
	}
}

// Resolve looks up or discovers the container ID associated with a cgroup ID and PID.
func (t *Tracker) Resolve(cgroupID uint64, pid uint32) string {
	if cgroupID == 0 {
		return ""
	}

	t.mu.RLock()
	id, found := t.cache[cgroupID]
	t.mu.RUnlock()

	if found {
		return id
	}

	// Not in cache: inspect /proc/<pid>/cgroup if available (Linux)
	containerID := t.lookupProcCgroup(pid)

	t.mu.Lock()
	if len(t.cache) >= t.maxEntries {
		// Evict an arbitrary entry
		for k := range t.cache {
			delete(t.cache, k)
			break
		}
	}
	t.cache[cgroupID] = containerID
	t.mu.Unlock()

	return containerID
}

// ExtractContainerID parses standard Linux /proc/<pid>/cgroup lines to extract container IDs.
func ExtractContainerID(cgroupContent string) string {
	for _, line := range strings.Split(cgroupContent, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if match := dockerRegex.FindStringSubmatch(line); len(match) > 1 {
			return truncateID(match[1])
		}
		if match := containerdRegex.FindStringSubmatch(line); len(match) > 1 {
			return truncateID(match[1])
		}
		if match := crioRegex.FindStringSubmatch(line); len(match) > 1 {
			return truncateID(match[1])
		}
		if match := genericHexRegex.FindString(line); len(match) == 64 {
			return truncateID(match)
		}
	}
	return ""
}

func (t *Tracker) lookupProcCgroup(pid uint32) string {
	if pid == 0 {
		return ""
	}
	path := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return ExtractContainerID(string(data))
}

func truncateID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
