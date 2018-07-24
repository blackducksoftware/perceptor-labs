package model

import (
	"time"

	u "github.com/jayunit100/vuln-sim/pkg/util"
)

//singleton-y vulnerability tool, only one per  simulation.
var vulns *VulnDetect

func init() {
	vulns = &VulnDetect{}
}

// Vuln detect is a tool that detects vulnerabilities...
// ... generically representing a security solution which
// might inspect containers or ports or ...

type VulnDetect struct {
	// map of projects -> vulnerabilities.
	Vulns map[string]int
}

func (v *VulnDetect) ActiveVulns(s []string) int {
	vn := 0
	for _, s0 := range s {
		if _, ok := v.Vulns[s0]; ok {
			vn++
		}
	}
	return vn
}

func (v *VulnDetect) Scan(i *Image) {
	u.AdvanceClock(2 * time.Minute)
	v.Vulns[i.Sha()] = i.vulns
	VulnsDetected.Inc()
}
