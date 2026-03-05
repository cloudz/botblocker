package blocker

import (
	"encoding/json"
	"errors"
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

// errAlreadyBlocked is returned when an IP is already in CSF's deny lists.
var errAlreadyBlocked = errors.New("already blocked in CSF")

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
		maxBlocksPerMinute: cfg.MaxBlocksPerMin,
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
	stateChanged := b.cleanExpiredBlocks()

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
		// Use prospective count to decide, but only persist after success
		count := b.state.OffenderCount[ip] + 1
		reason := strings.Join(sc.Reasons, "; ")

		if count > b.cfg.RepeatOffenderN {
			// Permanent block
			if err := b.blockPermanent(ip); err != nil {
				if errors.Is(err, errAlreadyBlocked) {
					b.log.Block("ALREADY_BLOCKED", "PERMANENT", ip, sc.Score, "permanent", reason)
					b.state.OffenderCount[ip] = count
					b.state.PermanentBlocked[ip] = true
				} else {
					b.log.Error("permanent block failed for %s: %v", ip, err)
				}
				continue
			}
			b.state.OffenderCount[ip] = count
			b.state.PermanentBlocked[ip] = true
			delete(b.state.CurrentTempBlocks, ip)
			b.log.Block("BLOCK", "PERMANENT", ip, sc.Score, "permanent", reason)
		} else {
			// Temporary block — scale TTL by score severity and repeat offense
			ttl := b.scaleTTL(sc.Score, count)
			if err := b.blockTemp(ip, ttl); err != nil {
				if errors.Is(err, errAlreadyBlocked) {
					b.log.Block("ALREADY_BLOCKED", "TEMP", ip, sc.Score,
						fmt.Sprintf("%ds", ttl), reason)
					b.state.OffenderCount[ip] = count
				} else {
					b.log.Error("temp block failed for %s: %v", ip, err)
				}
				continue
			}
			b.state.OffenderCount[ip] = count
			b.state.CurrentTempBlocks[ip] = time.Now().Add(time.Duration(ttl) * time.Second)
			b.log.Block("BLOCK", "TEMP", ip, sc.Score,
				fmt.Sprintf("%ds", ttl), reason)
		}

		blocked++
	}

	if blocked > 0 {
		b.log.Info("blocked %d IPs this cycle", blocked)
		stateChanged = true
	}
	if stateChanged {
		b.saveState()
	}
}

// isBlockedByCSF checks if an IP is already in CSF's deny or temp-deny lists.
func (b *Blocker) isBlockedByCSF(ip string) bool {
	// Check permanent deny list: csf -g returns exit 0 and includes
	// "csf.deny" or "DENY" in output if the IP is blocked
	out, err := exec.Command(b.cfg.CSFBin, "-g", ip).CombinedOutput()
	if err != nil {
		return false
	}
	s := string(out)
	return strings.Contains(s, "csf.deny") || strings.Contains(s, "DENY") ||
		strings.Contains(s, "csf.tempban") || strings.Contains(s, "TEMPBAN") ||
		strings.Contains(s, "Temporary Blocks")
}

// blockTemp issues a CSF temporary deny.
func (b *Blocker) blockTemp(ip string, ttlSeconds int) error {
	if b.dryRun {
		b.log.Info("[DRY RUN] would execute: csf -td %s %d BotBlocker", ip, ttlSeconds)
		return nil
	}

	// Check if already blocked by CSF (manually or by another tool)
	if b.isBlockedByCSF(ip) {
		return errAlreadyBlocked
	}

	// Use exec.Command with separate args — NEVER concatenate IP into a shell string
	cmd := exec.Command(b.cfg.CSFBin,
		"-td", ip, fmt.Sprintf("%d", ttlSeconds), "BotBlocker")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("csf -td: %w: %s", err, strings.TrimSpace(string(out)))
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

	// Check if already permanently blocked by CSF
	if b.isBlockedByCSF(ip) {
		return errAlreadyBlocked
	}

	// Remove from temp deny list first (ignore errors — may not be temp-blocked)
	_ = exec.Command(b.cfg.CSFBin, "-tr", ip).Run()

	cmd := exec.Command(b.cfg.CSFBin, "-d", ip, "BotBlocker-permanent")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("csf -d: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// scaleTTL returns a TTL in seconds scaled by score severity and repeat count.
// Base TTL is TempBlockSeconds (default 3600). Score above BlockScore doubles
// the TTL for every 50 extra points. Each repeat offense also doubles the TTL.
func (b *Blocker) scaleTTL(score, offenseCount int) int {
	ttl := b.cfg.TempBlockSeconds

	// Score multiplier: double for every 50 points above threshold
	excess := score - b.cfg.BlockScore
	for excess >= 50 {
		ttl *= 2
		excess -= 50
	}

	// Repeat offense multiplier: double for each prior offense
	for i := 1; i < offenseCount; i++ {
		ttl *= 2
	}

	// Cap at 7 days
	if ttl > 604800 {
		ttl = 604800
	}

	return ttl
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
// Returns true if any blocks were cleaned (state needs saving).
func (b *Blocker) cleanExpiredBlocks() bool {
	now := time.Now()
	cleaned := false
	for ip, expiry := range b.state.CurrentTempBlocks {
		if now.After(expiry) {
			delete(b.state.CurrentTempBlocks, ip)
			b.log.Unblock(ip)
			cleaned = true
		}
	}
	return cleaned
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
