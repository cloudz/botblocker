package scorer

import (
	"fmt"
	"strings"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
	"github.com/botblocker/botblocker/internal/parser"
)

// IPScore holds the computed threat score for a single IP.
type IPScore struct {
	IP            string
	Score         int
	Reasons       []string
	TotalRequests int
	RequestsPerMin float64
	ErrorRate     float64
	Domains       map[string]bool // unique domains this IP hit
}

// Scorer evaluates parsed log entries and produces per-IP threat scores.
type Scorer struct {
	cfg *config.Config
	log *logger.Logger
}

// New creates a new scorer.
func New(cfg *config.Config, log *logger.Logger) *Scorer {
	return &Scorer{cfg: cfg, log: log}
}

// Known scanner / attack tool User-Agent substrings (lowercase).
var scannerUAs = []string{
	"nuclei", "zgrab", "masscan", "nmap", "nikto", "sqlmap",
	"dirbuster", "gobuster", "wfuzz", "hydra", "burpsuite",
	"acunetix", "nessus", "openvas", "python-requests",
	"go-http-client", "scrapy", "libwww-perl", "metasploit",
	"curl", "wget",
}

// ScoreEntries analyses log entries and returns scored IPs.
func (s *Scorer) ScoreEntries(entries []parser.LogEntry) map[string]*IPScore {
	// Aggregate per IP
	perIP := make(map[string][]parser.LogEntry)
	for i := range entries {
		perIP[entries[i].IP] = append(perIP[entries[i].IP], entries[i])
	}

	scores := make(map[string]*IPScore, len(perIP))

	for ip, logs := range perIP {
		sc := &IPScore{
			IP:            ip,
			TotalRequests: len(logs),
			Domains:       make(map[string]bool),
		}

		// Collect unique domains and count errors
		var errCount int
		for _, e := range logs {
			if e.Domain != "" {
				sc.Domains[e.Domain] = true
			}
			if e.Status >= 400 && e.Status < 500 {
				errCount++
			}
		}

		// Calculate rates
		windowMinutes := float64(s.cfg.LogParseWindow) / 60.0
		if windowMinutes < 1 {
			windowMinutes = 1
		}
		sc.RequestsPerMin = float64(sc.TotalRequests) / windowMinutes
		if sc.TotalRequests > 0 {
			sc.ErrorRate = float64(errCount) / float64(sc.TotalRequests) * 100
		}

		// === Signal 1: High request rate ===
		if sc.RequestsPerMin >= float64(s.cfg.RequestsPerMinute) {
			sc.Score += s.cfg.ScoreHighRequestRate
			sc.Reasons = append(sc.Reasons, reasonf("%.0f req/min", sc.RequestsPerMin))
		}

		// === Signal 2: High error rate ===
		if sc.ErrorRate >= float64(s.cfg.ErrorRatePct) && sc.TotalRequests >= 5 {
			sc.Score += s.cfg.ScoreHighErrorRate
			sc.Reasons = append(sc.Reasons, reasonf("%.0f%% error rate", sc.ErrorRate))
		}

		// === Signal 3: Known scanner User-Agent ===
		if ua := detectScannerUA(logs); ua != "" {
			sc.Score += s.cfg.ScoreKnownScannerUA
			sc.Reasons = append(sc.Reasons, reasonf("scanner UA: %s", ua))
		}

		// === Signal 4: Honeypot path hit ===
		if hit := s.detectHoneypotHit(logs); hit != "" {
			sc.Score += s.cfg.ScoreHoneypotPathHit
			sc.Reasons = append(sc.Reasons, reasonf("honeypot hit: %s", hit))
		}

		// === Signal 5: Multi-vhost scan ===
		if len(sc.Domains) >= s.cfg.CrossDomainThresh {
			sc.Score += s.cfg.ScoreMultiVhostScan
			sc.Reasons = append(sc.Reasons, reasonf("%d domains scanned", len(sc.Domains)))
		}

		// === Signal 6: Known scanner path patterns ===
		if pathScore, paths := s.scorePathPatterns(logs); pathScore > 0 {
			sc.Score += pathScore
			sc.Reasons = append(sc.Reasons, reasonf("scanner paths: %s", strings.Join(paths, ", ")))
		}

		scores[ip] = sc
	}

	return scores
}

// detectScannerUA checks if any request from this IP uses a known scanner UA.
func detectScannerUA(logs []parser.LogEntry) string {
	for _, e := range logs {
		lower := strings.ToLower(e.UserAgent)
		for _, ua := range scannerUAs {
			if strings.Contains(lower, ua) {
				return ua
			}
		}
		// Empty UA is also suspicious
		if e.UserAgent == "" || e.UserAgent == "-" {
			return "empty-ua"
		}
	}
	return ""
}

// detectHoneypotHit checks if any request path matches a configured honeypot path.
func (s *Scorer) detectHoneypotHit(logs []parser.LogEntry) string {
	for _, e := range logs {
		path := strings.ToLower(e.Path)
		for _, hp := range s.cfg.HoneypotPathList {
			if strings.HasPrefix(path, strings.ToLower(hp)) {
				return hp
			}
		}
	}
	return ""
}

// Scanner path patterns — these indicate vulnerability scanning regardless of UA.
var scannerPathPatterns = []struct {
	pattern string
	points  int
}{
	{"/wp-login.php", 10},
	{"/wp-admin", 10},
	{"/xmlrpc.php", 10},
	{"/.env", 15},
	{"/.git/", 15},
	{"/.aws/", 20},
	{"/actuator/", 15},
	{"/phpmyadmin", 10},
	{"/admin/config", 10},
	{"/cgi-bin/", 10},
	{"/shell", 15},
	{"/c99", 15},
	{"/eval-stdin", 20},
	{"/vendor/phpunit", 15},
	{"/solr/", 10},
	{"/console/", 10},
	{"/api/v1/../../", 20},   // path traversal
	{"/../../../", 20},       // path traversal
	{"/etc/passwd", 20},      // LFI
	{"/proc/self/", 20},      // LFI
}

// scorePathPatterns checks for known vulnerability scanning paths.
// Returns the maximum single path score (we don't stack) and the matched paths.
func (s *Scorer) scorePathPatterns(logs []parser.LogEntry) (int, []string) {
	seen := make(map[string]bool)
	maxScore := 0

	for _, e := range logs {
		path := strings.ToLower(e.Path)
		for _, sp := range scannerPathPatterns {
			if strings.Contains(path, sp.pattern) && !seen[sp.pattern] {
				seen[sp.pattern] = true
				if sp.points > maxScore {
					maxScore = sp.points
				}
			}
		}
	}

	var paths []string
	for p := range seen {
		paths = append(paths, p)
	}

	return maxScore, paths
}

func reasonf(format string, args ...interface{}) string {
	s := fmt.Sprintf(format, args...)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSpace(s)
}

