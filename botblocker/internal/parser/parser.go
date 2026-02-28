package parser

import (
	"bufio"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
)

// LogEntry represents a single parsed access log line.
type LogEntry struct {
	IP        string
	Timestamp time.Time
	Method    string
	Path      string
	Status    int
	UserAgent string
	Domain    string // derived from DirectAdmin log path or Host header
}

// Parser reads and parses nginx + Apache access logs.
type Parser struct {
	cfg *config.Config
	log *logger.Logger
}

// New creates a new parser.
func New(cfg *config.Config, log *logger.Logger) *Parser {
	return &Parser{cfg: cfg, log: log}
}

// Standard combined log format:
// IP - - [timestamp] "METHOD PATH PROTO" status size "referer" "ua"
//
// Cloudflare variant (with CF-Connecting-IP logged):
// CF-IP PROXY-IP - - [timestamp] "METHOD PATH PROTO" status size "referer" "ua"
//
// We use a regex that captures: IP, timestamp, method, path, status, ua
var combinedRe = regexp.MustCompile(
	`^(\S+)\s+` +          // 1: IP (or CF real IP)
		`\S+\s+\S+\s+` +  // ident, auth
		`\[([^\]]+)\]\s+` + // 2: timestamp
		`"(\S+)\s+` +       // 3: method
		`(\S+)\s+` +        // 4: path
		`[^"]*"\s+` +       // protocol
		`(\d{3})\s+` +      // 5: status
		`\S+\s+` +          // size
		`"[^"]*"\s+` +      // referer
		`"([^"]*)"`,        // 6: user-agent
)

// Cloudflare variant: real IP is first field, proxy IP is second.
// DirectAdmin combined: same format but file path encodes domain.
// We detect CF by checking if the first IP is a Cloudflare proxy IP.
var cfRe = regexp.MustCompile(
	`^(\S+)\s+(\S+)\s+` +  // 1: real IP, 2: proxy IP
		`\S+\s+` +          // auth
		`\[([^\]]+)\]\s+` + // 3: timestamp
		`"(\S+)\s+` +       // 4: method
		`(\S+)\s+` +        // 5: path
		`[^"]*"\s+` +       // protocol
		`(\d{3})\s+` +      // 6: status
		`\S+\s+` +          // size
		`"[^"]*"\s+` +      // referer
		`"([^"]*)"`,        // 7: user-agent
)

// domainFromPath extracts domain name from DirectAdmin log paths like:
// /home/user/domains/example.com/logs/access.log
var domainPathRe = regexp.MustCompile(`/domains/([^/]+)/logs/`)

const maxLogLineLen = 8192

// ParseRecentEntries globs all configured log files and parses entries within
// the configured time window.
func (p *Parser) ParseRecentEntries() ([]LogEntry, error) {
	cutoff := time.Now().Add(-time.Duration(p.cfg.LogParseWindow) * time.Second)
	var all []LogEntry

	// Nginx logs
	if p.cfg.NginxLogGlob != "" {
		entries, err := p.parseGlob(p.cfg.NginxLogGlob, "", cutoff)
		if err != nil {
			p.log.Warn("nginx log parse error: %v", err)
		}
		all = append(all, entries...)
	}

	// Apache / DirectAdmin per-domain logs
	if p.cfg.ApacheLogGlob != "" {
		entries, err := p.parseGlob(p.cfg.ApacheLogGlob, "", cutoff)
		if err != nil {
			p.log.Warn("apache log parse error: %v", err)
		}
		all = append(all, entries...)
	}

	p.log.Info("parsed %d log entries from within the last %ds", len(all), p.cfg.LogParseWindow)
	return all, nil
}

func (p *Parser) parseGlob(pattern, defaultDomain string, cutoff time.Time) ([]LogEntry, error) {
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var all []LogEntry
	for _, path := range matches {
		// Extract domain from DirectAdmin-style paths
		domain := defaultDomain
		if m := domainPathRe.FindStringSubmatch(path); m != nil {
			domain = m[1]
		}

		entries, err := p.parseFile(path, domain, cutoff)
		if err != nil {
			p.log.Warn("error parsing %s: %v", path, err)
			continue
		}
		all = append(all, entries...)
	}
	return all, nil
}

func (p *Parser) parseFile(path, domain string, cutoff time.Time) ([]LogEntry, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// For large files, seek to tail to avoid reading gigabytes of old data.
	// Estimate: 256 bytes per line × max lines we'd process.
	const maxReadBytes = 50 * 1024 * 1024 // 50MB
	info, _ := f.Stat()
	if info != nil && info.Size() > maxReadBytes {
		if _, err := f.Seek(-maxReadBytes, io.SeekEnd); err == nil {
			// Discard partial first line after seek
			r := bufio.NewReader(f)
			r.ReadString('\n')
			// Continue with scanner from this position
			return p.scanLines(r, domain, cutoff)
		}
		// Fallback: read from start
		f.Seek(0, io.SeekStart)
	}

	return p.scanLines(bufio.NewReader(f), domain, cutoff)
}

func (p *Parser) scanLines(r io.Reader, domain string, cutoff time.Time) ([]LogEntry, error) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, maxLogLineLen)
	scanner.Buffer(buf, maxLogLineLen)

	var entries []LogEntry
	const maxLines = 500000 // hard safety cap
	lineCount := 0

	for scanner.Scan() {
		lineCount++
		if lineCount > maxLines {
			p.log.Warn("hit max line cap (%d), stopping parse", maxLines)
			break
		}

		line := scanner.Text()
		if len(line) > maxLogLineLen {
			continue // skip absurdly long lines (potential attack)
		}

		entry, ok := p.parseLine(line, domain)
		if !ok {
			continue
		}
		if entry.Timestamp.Before(cutoff) {
			continue
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

func (p *Parser) parseLine(line, domain string) (LogEntry, bool) {
	// Try standard combined format first
	m := combinedRe.FindStringSubmatch(line)
	if m != nil {
		ip := m[1]
		if net.ParseIP(ip) == nil {
			return LogEntry{}, false
		}

		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[2])
		if err != nil {
			return LogEntry{}, false
		}

		status, _ := strconv.Atoi(m[5])

		return LogEntry{
			IP:        ip,
			Timestamp: ts,
			Method:    sanitize(m[3], 10),
			Path:      sanitize(m[4], 2048),
			Status:    status,
			UserAgent: sanitize(m[6], 512),
			Domain:    domain,
		}, true
	}

	return LogEntry{}, false
}

// sanitize truncates a string and strips control characters to prevent
// log injection attacks.
func sanitize(s string, maxLen int) string {
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
