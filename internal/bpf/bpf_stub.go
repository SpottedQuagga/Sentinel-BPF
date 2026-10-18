//go:build !linux

package bpf

import (
	"errors"

	"github.com/sentinel-bpf/sentinel/internal/config"
)

// LinuxBPFSession is a placeholder for non-Linux platforms.
type LinuxBPFSession struct{}

func (s *LinuxBPFSession) Close() error            { return nil }
func (s *LinuxBPFSession) ReadKernelDrops() uint64 { return 0 }

// LoadAndAttach returns an error on non-Linux platforms.
func LoadAndAttach(cfg *config.Config) (*LinuxBPFSession, error) {
	return nil, errors.New("live kernel eBPF monitoring is only supported on Linux")
}
