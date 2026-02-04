package conf

import (
	"net"
	"paqet/internal/tnet"
)

type Forward struct {
	Listen_  string       `yaml:"listen"`
	Target_  string       `yaml:"target"`
	Protocol string       `yaml:"protocol"`
	Streams  int          `yaml:"streams"` // Number of parallel streams for UDP (default: 8)
	Listen   *net.UDPAddr `yaml:"-"`
	Target   *tnet.Addr   `yaml:"-"`
}

func (c *Forward) setDefaults() {
	if c.Streams == 0 {
		c.Streams = 8 // Default to 8 parallel streams
	}
}

func (c *Forward) validate() []error {
	var errors []error
	l, err := validateAddr(c.Listen_, true)
	if err != nil {
		errors = append(errors, err)
	}
	c.Listen = l

	t, err := tnet.NewAddr(c.Target_)
	if err != nil {
		errors = append(errors, err)
	}
	c.Target = t

	// Clamp streams to reasonable range
	if c.Streams < 1 {
		c.Streams = 1
	} else if c.Streams > 64 {
		c.Streams = 64
	}

	return errors
}
