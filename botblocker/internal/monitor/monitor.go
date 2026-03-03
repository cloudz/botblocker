package monitor

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
)

// Monitor watches system load and triggers parse cycles.
type Monitor struct {
	cfg  *config.Config
	log  *logger.Logger
	mu   sync.RWMutex
	load float64
}

// New creates a new load monitor.
func New(cfg *config.Config, log *logger.Logger) *Monitor {
	return &Monitor{cfg: cfg, log: log}
}

// CurrentLoad returns the last observed 1-minute load average.
func (m *Monitor) CurrentLoad() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.load
}

// Run starts the monitor loop. It sends on triggerCh when a parse cycle should run.
// It blocks until stopCh is closed.
func (m *Monitor) Run(triggerCh chan<- string, stopCh <-chan struct{}) {
	pollTick := time.NewTicker(time.Duration(m.cfg.PollInterval) * time.Second)
	defer pollTick.Stop()

	// Baseline scan regardless of load
	baselineTick := time.NewTicker(time.Duration(m.cfg.BaselineSeconds) * time.Second)
	defer baselineTick.Stop()

	// Cooldown: after a load-triggered scan, suppress further triggers
	var lastLoadTrigger time.Time
	cooldown := time.Duration(m.cfg.CooldownSeconds) * time.Second

	for {
		select {
		case <-pollTick.C:
			load, err := readLoadAvg()
			if err != nil {
				m.log.Error("read loadavg: %v", err)
				continue
			}

			m.mu.Lock()
			m.load = load
			m.mu.Unlock()

			threshold := m.cfg.LoadThreshold()
			if load >= threshold {
				if time.Since(lastLoadTrigger) >= cooldown {
					m.log.Info("load %.2f >= threshold %.2f — triggering parse cycle", load, threshold)
					lastLoadTrigger = time.Now()
					select {
					case triggerCh <- "load":
					default: // already pending
					}
				} else {
					m.log.Debug("load %.2f >= threshold but in cooldown", load)
				}
			}

		case <-baselineTick.C:
			m.log.Debug("baseline scan triggered")
			select {
			case triggerCh <- "baseline":
			default:
			}

		case <-stopCh:
			return
		}
	}
}

// readLoadAvg reads the 1-minute load average from /proc/loadavg.
func readLoadAvg() (float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, fmt.Errorf("read /proc/loadavg: %w", err)
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("unexpected loadavg format")
	}
	return strconv.ParseFloat(fields[0], 64)
}
