package conf

import (
	"fmt"
	"slices"
)

type Transport struct {
	Protocol string `yaml:"protocol"`
	Conn     int    `yaml:"conn"`
	KCP      *KCP   `yaml:"kcp"`
	QUIC     *QUIC  `yaml:"quic"`
	UDP      *UDP   `yaml:"udp"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}
	switch t.Protocol {
	case "kcp":
		if t.KCP == nil {
			t.KCP = &KCP{}
		}
		t.KCP.setDefaults(role)
	case "quic":
		if t.QUIC == nil {
			t.QUIC = &QUIC{}
		}
		t.QUIC.setDefaults(role)
	case "udp":
		if t.UDP == nil {
			t.UDP = &UDP{}
		}
		t.UDP.setDefaults(role)
	case "auto":
		// In auto mode, set defaults for all configured protocols.
		if t.KCP != nil {
			t.KCP.setDefaults(role)
		}
		if t.QUIC != nil {
			t.QUIC.setDefaults(role)
		}
		if t.UDP != nil {
			t.UDP.setDefaults(role)
		}
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{"kcp", "quic", "udp", "auto"}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("transport conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp":
		if t.KCP == nil {
			errors = append(errors, fmt.Errorf("KCP configuration is required when protocol is 'kcp'"))
		} else {
			errors = append(errors, t.KCP.validate()...)
		}
	case "quic":
		if t.QUIC == nil {
			errors = append(errors, fmt.Errorf("QUIC configuration is required when protocol is 'quic'"))
		} else {
			errors = append(errors, t.QUIC.validate()...)
		}
	case "udp":
		if t.UDP == nil {
			errors = append(errors, fmt.Errorf("UDP configuration is required when protocol is 'udp'"))
		} else {
			errors = append(errors, t.UDP.validate()...)
		}
	case "auto":
		// At least two protocols must be configured for auto mode.
		configured := 0
		if t.KCP != nil {
			configured++
			errors = append(errors, t.KCP.validate()...)
		}
		if t.QUIC != nil {
			configured++
			errors = append(errors, t.QUIC.validate()...)
		}
		if t.UDP != nil {
			configured++
			errors = append(errors, t.UDP.validate()...)
		}
		if configured < 2 {
			errors = append(errors, fmt.Errorf("auto mode requires at least 2 protocol configurations (kcp, quic, udp)"))
		}
	}

	return errors
}
