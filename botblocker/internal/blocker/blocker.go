package blocker

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
	"github.com/botblocker/botblocker/internal/scorer"
)

// Strict IP validation: only IPv4 dotted-decimal or IPv6 hex-colon.
// This is the gate before anything reaches a shell command.
var ipv4Re = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
var ipv6Re = regexp.MustCompile(`^[0-9a-fA-F:]+$`)

// State persists between daemon restarts.
type State struct {
	// OffenderCount tracks how many times an IP has been temp-blocked.
	OffenderCount map[string]int `json:"offender_count"`
	// PermanentBlocked tracks IPs that have been permanently blocked.
	PermanentBlocked map[string]bool `json:"permanent_blocked"`
	// CurrentTempBlocks tracks currently active temp blocks and when they expire.
	CurrentTempBlocks map[string]time.Time `json:"current_temp_blocks"`
}

// Blocker handles IP blocking decisions and CSF interaction.
type Blocker struct {
	cfg   *config.Config
	log   *logger.Logger
	mu    sync.Mutex
	state State

	// Rate limit: max 20 blocks per minute
	blockTimes []time.Time
	maxBlocksPerMinute int

	dryRun bool
}

// New creates a new blocker and loads persisted state.
func New(cfg *config.Config, log *logger.Logger, dryRun bool) (*Blocker, error) {
	b := &Blocker{
		cfg:    cfg,
		log:    log,
		dryRun: dryRun,
		state: State{
			OffenderCount:     make(map[string]int),
			PermanentBlocked:  make(map[string]bool),
			CurrentTempBlocks: make(map[string]time.Time),
		},
		maxBlocksPerMinute: 20,
	}

	if err := b.loadState(); err != nil {
		log.Warn("could not load state (starting fresh): %v", err)
	}

	return b, nil
}

// ProcessScores evaluates scored IPs and blocks those above threshold.
func (b *Blocker) ProcessScores(scores map[string]*scorer.IPScore) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Reload whitelist on every cycle (allows live edits)
	if err := b.cfg.LoadWhitelist(); err != nil {
		b.log.Error("failed to reload whitelist: %v", err)
	}

	// Clean expired temp blocks
	b.cleanExpiredBlocks()

	blocked := 0
	for ip, sc := range scores {
		if sc.Score < b.cfg.BlockScore {
			continue
		}

		// === Gate 1: Validate IP string (SECURITY CRITICAL) ===
		if !isValidIP(ip) {
			b.log.Warn("rejecting invalid IP string: %q", sanitizeForLog(ip))
			continue
		}

		// === Gate 2: Whitelist check ===
		if b.cfg.IsWhitelisted(ip) {
			b.log.Debug("skipping whitelisted IP %s (score %d)", ip, sc.Score)
			continue
		}

		// === Gate 3: Already blocked? ===
		if b.state.PermanentBlocked[ip] {
			continue
		}
		if expiry, ok := b.state.CurrentTempBlocks[ip]; ok && time.Now().Before(expiry) {
			continue
		}

		// === Gate 4: Rate limit (anti log-poisoning) ===
		if !b.checkRateLimit() {
			b.log.Warn("block rate limit reached (20/min), deferring remaining blocks")
			break
		}

		// === Decision: temp or permanent ===
		b.state.OffenderCount[ip]++
		count := b.state.OffenderCount[ip]
		reason := strings.Join(sc.Reasons, "; ")

		if count > b.cfg.RepeatOffenderN {
			// Permanent block
			if err := b.blockPermanent(ip); err != nil {
				b.log.Error("permanent block failed for %s: %v", ip, err)
				continue
			}
			b.state.PermanentBlocked[ip] = true
			delete(b.state.CurrentTempBlocks, ip)
			b.log.Block("BLOCK", "PERMANENT", ip, sc.Score, "permanent", reason)
		} else {
			// Temporary block
			ttl := b.cfg.TempBlockSeconds
			if err := b.blockTemp(ip, ttl); err != nil {
				b.log.Error("temp block failed for %s: %v", ip, err)
				continue
			}
			b.state.CurrentTempBlocks[ip] = time.Now().Add(time.Duration(ttl) * time.Second)
			b.log.Block("BLOCK", "TEMP", ip, sc.Score,
				fmt.Sprintf("%ds", ttl), reason)
		}

		blocked++
	}

	if blocked > 0 {
		b.log.Info("blocked %d IPs this cycle", blocked)
		b.saveState()
	}
}

// blockTemp issues a CSF temporary deny.
func (b *Blocker) blockTemp(ip string, ttlSeconds int) error {
	if b.dryRun {
		b.log.Info("[DRY RUN] would execute: csf -td %s %d BotBlocker", ip, ttlSeconds)
		return nil
	}

	// Use exec.Command with separate args — NEVER concatenate IP into a shell string
	cmd := exec.Command(b.cfg.CSFBin,
		"-td", ip, fmt.Sprintf("%d", ttlSeconds), "BotBlocker")
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("csf -td: %w", err)
	}
	return nil
}

// blockPermanent issues a CSF permanent deny.
// It removes any existing temp block first, since csf -d fails if the IP
// is already in the temp deny list.
func (b *Blocker) blockPermanent(ip string) error {
	if b.dryRun {
		b.log.Info("[DRY RUN] would execute: csf -tr %s; csf -d %s BotBlocker-permanent", ip, ip)
		return nil
	}

	// Remove from temp deny list first (ignore errors — may not be temp-blocked)
	_ = exec.Command(b.cfg.CSFBin, "-tr", ip).Run()

	cmd := exec.Command(b.cfg.CSFBin, "-d", ip, "BotBlocker-permanent")
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("csf -d: %w", err)
	}
	return nil
}

// checkRateLimit enforces max 20 blocks per minute.
func (b *Blocker) checkRateLimit() bool {
	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Prune old entries
	var recent []time.Time
	for _, t := range b.blockTimes {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= b.maxBlocksPerMinute {
		b.blockTimes = recent
		return false
	}

	b.blockTimes = append(recent, now)
	return true
}

// cleanExpiredBlocks removes temp blocks that have expired.
func (b *Blocker) cleanExpiredBlocks() {
	now := time.Now()
	for ip, expiry := range b.state.CurrentTempBlocks {
		if now.After(expiry) {
			delete(b.state.CurrentTempBlocks, ip)
			b.log.Unblock(ip)
		}
	}
}

// isValidIP strictly validates an IP string before it goes anywhere near a shell.
func isValidIP(ip string) bool {
	// First: must parse as a valid Go net.IP
	if net.ParseIP(ip) == nil {
		return false
	}
	// Second: must match our strict character regex (defense in depth)
	return ipv4Re.MatchString(ip) || ipv6Re.MatchString(ip)
}

// sanitizeForLog makes a string safe for log output (prevent log injection).
func sanitizeForLog(s string) string {
	if len(s) > 100 {
		s = s[:100]
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r < 127 {
			b.WriteRune(r)
		} else {
			b.WriteString("?")
		}
	}
	return b.String()
}

// --- State persistence ---

func (b *Blocker) loadState() error {
	path := filepath.Clean(b.cfg.StateFile)
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("corrupt state file: %w", err)
	}

	if state.OffenderCount != nil {
		b.state.OffenderCount = state.OffenderCount
	}
	if state.PermanentBlocked != nil {
		b.state.PermanentBlocked = state.PermanentBlocked
	}
	if state.CurrentTempBlocks != nil {
		b.state.CurrentTempBlocks = state.CurrentTempBlocks
	}

	b.log.Info("loaded state: %d offenders, %d permanent blocks",
		len(b.state.OffenderCount), len(b.state.PermanentBlocked))
	return nil
}

func (b *Blocker) saveState() {
	path := filepath.Clean(b.cfg.StateFile)

	// Ensure directory exists with restrictive permissions
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		b.log.Error("create state dir: %v", err)
		return
	}

	data, err := json.MarshalIndent(b.state, "", "  ")
	if err != nil {
		b.log.Error("marshal state: %v", err)
		return
	}

	// Atomic write: write to temp file, then rename
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		b.log.Error("write state: %v", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		b.log.Error("rename state: %v", err)
		os.Remove(tmp)
	}
}

// GetState returns a copy of the current state (for --once output).
func (b *Blocker) GetState() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
