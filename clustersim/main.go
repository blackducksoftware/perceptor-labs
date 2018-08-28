package main

import (
	"fmt"
	"os"
	"time"

	// <- ui shortcut, optional

	"github.com/blackducksoftware/vuln-sim/pkg/model3"
	"github.com/blackducksoftware/vuln-sim/pkg/view"
	"github.com/olekukonko/tablewriter"
	"github.com/pkg/profile"
	"github.com/sirupsen/logrus"
)

// <- ui shortcut, optional
func test() {
	data := [][]string{}

	regMax := 5000
	scanMax := 100

	header := func() []string {
		h := []string{}
		i := 0
		h = append(h, "--------")

		for ScansPerMinute := 1; ScansPerMinute < scanMax; ScansPerMinute += 20 {
			i++
			h = append(h, fmt.Sprintf("S/M:%v", ScansPerMinute))
		}
		return h
	}()

	for regSize := 1000; regSize < regMax; regSize += 1000 {
		registries := []string{fmt.Sprintf("regsize:%v", regSize)}
		for ScansPerMinute := 1; ScansPerMinute < scanMax; ScansPerMinute += 20 {
			c := &model3.ClusterSim{
				ChurnProbability: .10,
				EventsPerMinute:  10,
				MaxPodsPerApp:    10,
				NumUsers:         100,
				RegistrySize:     regSize,
				ScansPerMinute:   float32(ScansPerMinute),
				SimTime:          time.Duration(5) * time.Hour,
			}
			c.Simulate()
			registries = append(registries, fmt.Sprintf("%v", c.VulnerabilityTime()))
		}
		data = append(data, registries)
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.Append(header)
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}

func ExperimentalSimulation1() {
	base := &model3.ClusterSim{
		ChurnProbability: .9,
		EventsPerMinute:  2,
		MaxPodsPerApp:    10,
		NumUsers:         10,
		RegistrySize:     10000,
		ScansPerMinute:   2,
		SimTime:          time.Duration(24) * time.Hour,
	}

	done := make(chan bool)

	go func() {
		done <- base.Simulate()
	}()

	<-done
	/**
		for i := 0; i < base.TotalActions(); i += 100 {
			logrus.Infof("%v: %v", i, base.VulnsAt(i))
			time.Sleep(500 * time.Millisecond)
		}
	**/
	logrus.Infof("viz in 10s")

	view.LaunchUI(map[string]*model3.ClusterSim{
		"2xScanRate:": base,
	})
}

func main() {
	defer profile.Start().Stop()
	ExperimentalSimulation1()
}
