package detect

import (
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/mattrmcg/ids/internal/types"
)

type Attempt struct {
	TS   time.Time
	Port uint16
}

type ScanDetector struct {
	connectionMap map[netip.Addr][]Attempt
	mu            sync.Mutex
	cleanupWindow time.Duration
	stopCh        chan struct{}
}

func CreateScanDetector() *ScanDetector {
	cm := make(map[netip.Addr][]Attempt)
	sd := &ScanDetector{
		connectionMap: cm,
		cleanupWindow: 5 * time.Second,
		stopCh:        make(chan struct{}),
	}
	go sd.cleanupRoutine()
	return sd
}

func (sd *ScanDetector) DetectPortscan(ev types.Event) {
	if ev.SYN {
		var attempt Attempt = Attempt{TS: ev.TS, Port: ev.DstPort}
		sd.mu.Lock()
		sd.connectionMap[ev.SrcIP] = append(sd.connectionMap[ev.SrcIP], attempt)
		sd.mu.Unlock()
		if len(sd.connectionMap[ev.SrcIP]) > 50 {
			log.Printf("Portscan detected from %s\n at %s", ev.SrcIP, ev.TS.String())
		}
	}
}

func (sd *ScanDetector) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			sd.mu.Lock()
			cutoff := time.Now().Add(-sd.cleanupWindow)
			for ip, attempts := range sd.connectionMap {
				var filtered []Attempt
				for _, att := range attempts {
					if att.TS.After(cutoff) {
						filtered = append(filtered, att)
					}
				}
				if len(filtered) > 0 {
					sd.connectionMap[ip] = filtered
				} else {
					delete(sd.connectionMap, ip)
				}
			}
			sd.mu.Unlock()
		case <-sd.stopCh:
			return
		}
	}
}

func (sd *ScanDetector) Stop() {
	close(sd.stopCh)
}
