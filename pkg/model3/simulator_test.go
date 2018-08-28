package model3

import (
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestLong(t *testing.T) {
	c := &ClusterSim{
		ChurnProbability: .9, // high churn, faster exposure of vulns
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         2,
		RegistrySize:     60, // small registry, faster convergence to 0 unknown vulns
		ScansPerMinute:   float32(1),
		SimTime:          time.Duration(24*365) * time.Hour,
	}
	c.Simulate()
}

func TestSimpleConvergence(t *testing.T) {
	c := &ClusterSim{
		ChurnProbability: .9, // high churn, faster exposure of vulns
		EventsPerMinute:  10,
		MaxPodsPerApp:    10,
		NumUsers:         5,
		RegistrySize:     5, // small registry, faster convergence to 0 unknown vulns
		ScansPerMinute:   float32(2),
		SimTime:          time.Duration(10) * time.Minute,
	}

	c.Simulate()
	if len(c.Registry.Images) > c.RegistrySize || (len(c.st.Scanned) > c.RegistrySize) {
		logrus.Infof("Registry or scans size too big ! (%v %v )> %v, scanned", len(c.st.Scanned), len(c.Registry.Images), c.RegistrySize)
		panic("reg size")
		t.Fail()
		return
	}

	vulns := c.Vulns()
	if len(vulns) == 0 {
		t.Fail()
	}
	logrus.Infof("total # of events : %v", len(vulns))

	for i := 0; i < len(vulns); i++ {
		logrus.Infof("vuln count @ %v (%v) debug: %v ****** %v", i, vulns[i], c.History.ImagesAt(i), c.st.History)
	}

	logrus.Info(c.st.Debug())

	// By the end of the sim, we should easily be @ 0 vulnerabilities.
	lastElements := []int{
		len(vulns) - 1,
		len(vulns) - 2,
		len(vulns) - 3,
		len(vulns) - 4,
		len(vulns) - 5,
		len(vulns) - 6,
		len(vulns) - 7,
	}

	nonZero := false
	for eventID, vulns := range c.Vulns() {
		if nonZero {
			continue
		}
		if vulns > 0 {
			nonZero = true
			logrus.Infof("whew ! Found at least one real data point :) %v / %v ", eventID, vulns)
		}
	}
	if !nonZero {
		t.Fail()
	}

	for _, lastIndex := range lastElements {
		if vulns[lastIndex] > 0 {
			logrus.Infof("The last entry should be 0 vuln !.. but found a vuln %v @ event %v", vulns[lastIndex], lastIndex)
			t.Fail()
		}
	}
}

func TestTimeSimulation(t *testing.T) {
	hours := 48
	scansPerMinute := 2
	totalScansExpected := hours * scansPerMinute * 60
	c := &ClusterSim{
		ChurnProbability: .9, // high churn, faster exposure of vulns
		EventsPerMinute:  9,
		MaxPodsPerApp:    10,
		NumUsers:         100,
		RegistrySize:     50, // small registry, faster convergence to 0 unknown vulns
		ScansPerMinute:   float32(scansPerMinute),
		SimTime:          time.Duration(hours) * time.Hour,
	}

	c.Simulate()
	logrus.Infof("total time was %v, needed ~ %v minutes", c.TimeSoFar(), c.SimTime)

	if c.TimeSoFar() > 49*time.Hour {
		logrus.Infof("WAY TOOO LONGGGG!!")
		t.Fail()
	}
	if c.TimeSoFar() < 47*time.Hour {
		logrus.Infof("WAY TOOO SHORT!!")
		t.Fail()
	}

	// Now verify events.
	if float32(c.eventsProcessed) > 1.1*float32(c.EventsPerMinute*60*hours) {
		logrus.Infof("Too many events, %v, expected %v", c.eventsProcessed, c.EventsPerMinute*48*60)
		t.Fail()
	} else if float32(c.eventsProcessed) < .9*float32(c.EventsPerMinute*60*hours) {
		logrus.Infof("Too FEW events, %v, expected %v", c.eventsProcessed, c.EventsPerMinute*48*60)
		t.Fail()
	}
	if float32(c.scans) > 1.1*float32(totalScansExpected) {
		logrus.Infof("Too MANY *scans*, %v, expected %v", c.scans, totalScansExpected)
		t.Fail()
	} else if float32(c.scans) < .9*float32(totalScansExpected) {
		logrus.Infof("Too FEW *scans*, %v, expected %v", c.scans, totalScansExpected)
		t.Fail()
	}
}
