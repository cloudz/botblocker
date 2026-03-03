package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Config holds all configuration for BotBlocker.
type Config struct {
	// [general]
	PollInterval   int    // seconds between load checks
	LogParseWindow int    // seconds of log history to analyse
	LogLevel       string // debug / info / warn / error

	// [thresholds]
	LoadMultiplier    float64 // trigger when load > cores × this
	BlockScore        int     // minimum score to block
	RequestsPerMinute int     // req/min for rate score
	ErrorRatePct      int     // % of 4xx for error score
	RepeatOffenderN   int     // temp blocks before permanent
	TempBlockSeconds  int     // TTL for temporary blocks
	MaxBlocksPerMin   int     // max blocks per minute (rate limit)
	CooldownSeconds   int     // seconds to suppress triggers after a load scan
	BaselineSeconds   int     // seconds between baseline scans

	// [paths]
	NginxLogGlob  string
	ApacheLogGlob string
	WhitelistFile string
	BlockedLog    string
	DaemonLog     string
	StateFile     string
	HoneypotPaths string

	// [csf]
	CSFBin string

	// [scoring]
	ScoreHighRequestRate int
	ScoreHighErrorRate   int
	ScoreKnownScannerUA  int
	ScoreHoneypotPathHit int
	ScoreMultiVhostScan  int
	CrossDomainThresh    int

	// Runtime (not from file)
	NumCPU         int
	WhitelistNets  []*net.IPNet
	HoneypotPathList []string
}

// DefaultConfig returns safe defaults matching the spec.
func DefaultConfig() *Config {
	return &Config{
		PollInterval:   10,
		LogParseWindow: 300,
		LogLevel:       "info",

		LoadMultiplier:    1.5,
		BlockScore:        60,
		RequestsPerMinute: 50,
		ErrorRatePct:      80,
		RepeatOffenderN:   3,
		TempBlockSeconds:  3600,
		MaxBlocksPerMin:   20,
		CooldownSeconds:   300,
		BaselineSeconds:   600,

		NginxLogGlob:  "/var/log/nginx/domains/*.log",
		ApacheLogGlob: "/var/log/httpd/domains/*.log, /home/*/domains/*/logs/access.log",
		WhitelistFile: "/usr/local/botblocker/whitelist.txt",
		BlockedLog:    "/var/log/botblocker/blocked.log",
		DaemonLog:     "/var/log/botblocker/botblocker.log",
		StateFile:     "/var/lib/botblocker/state.json",
		HoneypotPaths: "/usr/local/botblocker/honeypot_paths.txt",

		CSFBin: "/usr/sbin/csf",

		ScoreHighRequestRate: 30,
		ScoreHighErrorRate:   25,
		ScoreKnownScannerUA:  20,
		ScoreHoneypotPathHit: 40,
		ScoreMultiVhostScan:  15,
		CrossDomainThresh:    3,

		NumCPU: runtime.NumCPU(),
	}
}

// LoadFromFile parses an INI-style config file and merges with defaults.
func LoadFromFile(path string) (*Config, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return nil, fmt.Errorf("config path must be absolute: %s", path)
	}

	f, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat config: %w", err)
	}
	if info.Size() > 1<<20 {
		return nil, fmt.Errorf("config file too large: %d bytes", info.Size())
	}

	cfg := DefaultConfig()
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' || line[0] == '[' {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("line %d: invalid format", lineNum)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if err := cfg.set(key, val); err != nil {
			return nil, fmt.Errorf("line %d (%s): %w", lineNum, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	if err := cfg.LoadWhitelist(); err != nil {
		return nil, fmt.Errorf("whitelist: %w", err)
	}
	if err := cfg.loadHoneypotPaths(); err != nil {
		return nil, fmt.Errorf("honeypot paths: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) set(key, val string) error {
	switch key {
	// [general]
	case "poll_interval":
		return setInt(&c.PollInterval, val, 1, 300)
	case "log_parse_window":
		return setInt(&c.LogParseWindow, val, 10, 3600)
	case "log_level":
		switch val {
		case "debug", "info", "warn", "error":
			c.LogLevel = val
		default:
			return fmt.Errorf("invalid log_level: %s", val)
		}
	// [thresholds]
	case "load_multiplier":
		v, err := strconv.ParseFloat(val, 64)
		if err != nil || v <= 0 || v > 100 {
			return fmt.Errorf("invalid load_multiplier")
		}
		c.LoadMultiplier = v
	case "block_score":
		return setInt(&c.BlockScore, val, 1, 10000)
	case "requests_per_minute":
		return setInt(&c.RequestsPerMinute, val, 1, 100000)
	case "error_rate_pct":
		return setInt(&c.ErrorRatePct, val, 1, 100)
	case "repeat_offender_n":
		return setInt(&c.RepeatOffenderN, val, 1, 100)
	case "temp_block_seconds":
		return setInt(&c.TempBlockSeconds, val, 60, 604800)
	case "max_blocks_per_min":
		return setInt(&c.MaxBlocksPerMin, val, 1, 1000)
	case "cooldown_seconds":
		return setInt(&c.CooldownSeconds, val, 10, 3600)
	case "baseline_seconds":
		return setInt(&c.BaselineSeconds, val, 30, 86400)
	// [paths]
	case "nginx_log_glob":
		c.NginxLogGlob = val
	case "apache_log_glob":
		c.ApacheLogGlob = val
	case "whitelist_file":
		c.WhitelistFile = val
	case "blocked_log":
		c.BlockedLog = val
	case "daemon_log":
		c.DaemonLog = val
	case "state_file":
		c.StateFile = val
	case "honeypot_paths":
		c.HoneypotPaths = val
	// [csf]
	case "csf_bin":
		c.CSFBin = val
	// [scoring]
	case "high_request_rate":
		return setInt(&c.ScoreHighRequestRate, val, 0, 1000)
	case "high_error_rate":
		return setInt(&c.ScoreHighErrorRate, val, 0, 1000)
	case "known_scanner_ua":
		return setInt(&c.ScoreKnownScannerUA, val, 0, 1000)
	case "honeypot_path_hit":
		return setInt(&c.ScoreHoneypotPathHit, val, 0, 1000)
	case "multi_vhost_scan":
		return setInt(&c.ScoreMultiVhostScan, val, 0, 1000)
	case "cross_domain_thresh":
		return setInt(&c.CrossDomainThresh, val, 1, 1000)
	default:
		return fmt.Errorf("unknown config key: %s", key)
	}
	return nil
}

func setInt(target *int, val string, min, max int) error {
	v, err := strconv.Atoi(val)
	if err != nil {
		return fmt.Errorf("not an integer: %s", val)
	}
	if v < min || v > max {
		return fmt.Errorf("value %d out of range [%d, %d]", v, min, max)
	}
	*target = v
	return nil
}

// LoadWhitelist parses the whitelist file into IPNets. Called on every parse cycle
// so edits take effect without a restart.
func (c *Config) LoadWhitelist() error {
	c.WhitelistNets = nil

	f, err := os.Open(filepath.Clean(c.WhitelistFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// Bare IP → CIDR
		if !strings.Contains(line, "/") {
			if strings.Contains(line, ":") {
				line += "/128"
			} else {
				line += "/32"
			}
		}

		_, network, err := net.ParseCIDR(line)
		if err != nil {
			return fmt.Errorf("invalid whitelist entry %q: %w", line, err)
		}
		c.WhitelistNets = append(c.WhitelistNets, network)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	c.addSelfIPs()
	return nil
}

// addSelfIPs detects the server's own IP addresses and adds them to the
// whitelist so that BotBlocker never blocks its own traffic.
func (c *Config) addSelfIPs() {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Skip loopback — already covered by whitelist file
		if ip.IsLoopback() {
			continue
		}
		var mask net.IPMask
		if ip.To4() != nil {
			mask = net.CIDRMask(32, 32)
		} else {
			mask = net.CIDRMask(128, 128)
		}
		c.WhitelistNets = append(c.WhitelistNets, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
	}
}

func (c *Config) loadHoneypotPaths() error {
	c.HoneypotPathList = nil

	f, err := os.Open(filepath.Clean(c.HoneypotPaths))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		c.HoneypotPathList = append(c.HoneypotPathList, line)
	}
	return scanner.Err()
}

// IsWhitelisted checks if an IP is covered by any whitelist entry.
func (c *Config) IsWhitelisted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, network := range c.WhitelistNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (c *Config) validate() error {
	if c.PollInterval < 1 {
		return fmt.Errorf("poll_interval must be >= 1")
	}
	if c.BlockScore < 1 {
		return fmt.Errorf("block_score must be >= 1")
	}
	if c.TempBlockSeconds < 60 {
		return fmt.Errorf("temp_block_seconds must be >= 60")
	}
	return nil
}

// LoadThreshold returns the computed load threshold: cores × multiplier.
func (c *Config) LoadThreshold() float64 {
	return float64(c.NumCPU) * c.LoadMultiplier
}
