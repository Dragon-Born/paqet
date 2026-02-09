//go:build linux

package socket

import (
	"fmt"
	"os/exec"
	"paqet/internal/flog"
)

// iptablesGuard manages iptables rules that prevent the kernel from
// interfering with raw TCP traffic on a given port:
//   - NOTRACK in raw table prevents conntrack from tracking the port
//   - RST DROP in mangle table prevents kernel from sending RSTs
//
// Without these rules, the kernel sends RSTs for incoming TCP packets
// on ports without a real socket, causing stateful firewalls/cloud
// security groups to tear down the connection state and drop subsequent
// server responses.
type iptablesGuard struct {
	port  int
	rules []iptRule
}

type iptRule struct {
	table string
	chain string
	args  []string
}

func newIptablesGuard(port int) *iptablesGuard {
	p := fmt.Sprint(port)
	return &iptablesGuard{
		port: port,
		rules: []iptRule{
			{table: "raw", chain: "PREROUTING", args: []string{"-p", "tcp", "--dport", p, "-j", "NOTRACK"}},
			{table: "raw", chain: "OUTPUT", args: []string{"-p", "tcp", "--sport", p, "-j", "NOTRACK"}},
			{table: "mangle", chain: "OUTPUT", args: []string{"-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"}},
		},
	}
}

func (g *iptablesGuard) Install() {
	for _, r := range g.rules {
		args := append([]string{"-t", r.table, "-C", r.chain}, r.args...)
		if exec.Command("iptables", args...).Run() == nil {
			flog.Infof("iptables: %s/%s rule for port %d already exists", r.table, r.chain, g.port)
			continue
		}
		args[2] = "-I" // insert at top
		if err := exec.Command("iptables", args...).Run(); err != nil {
			flog.Warnf("iptables: failed to add %s/%s rule for port %d: %v", r.table, r.chain, g.port, err)
		} else {
			flog.Infof("iptables: added %s/%s rule for port %d", r.table, r.chain, g.port)
		}
	}
}

func (g *iptablesGuard) Remove() {
	for _, r := range g.rules {
		args := append([]string{"-t", r.table, "-D", r.chain}, r.args...)
		_ = exec.Command("iptables", args...).Run()
	}
}
