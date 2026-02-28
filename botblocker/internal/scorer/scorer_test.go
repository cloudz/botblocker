package scorer

import (
	"testing"
	"time"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
	"github.com/botblocker/botblocker/internal/parser"
)

func newTestScorer() *Scorer {
	cfg := config.DefaultConfig()
	cfg.HoneypotPathList = []string{"/.env", "/wp-login.php", "/.git/config"}
	log := logger.NewStdout("error")
	return New(cfg, log)
}

func TestScoreHighRequestRate(t *testing.T) {
	s := newTestScorer()
	now := time.Now()

	// Generate 300 requests in a 5-minute window = 60 req/min (above threshold of 50)
	var entries []parser.LogEntry
	for i := 0; i < 300; i++ {
		entries = append(entries, parser.LogEntry{
			IP:        "1.2.3.4",
			Timestamp: now,
			Method:    "GET",
			Path:      "/",
			Status:    200,
			UserAgent: "Mozilla/5.0",
		})
	}

	scores := s.ScoreEntries(entries)
	sc := scores["1.2.3.4"]
	if sc == nil {
		t.Fatal("no score for IP")
	}
	if sc.Score < 30 {
		t.Errorf("expected score >= 30 for high rate, got %d", sc.Score)
	}
}

func TestScoreHoneypotHit(t *testing.T) {
	s := newTestScorer()
	entries := []parser.LogEntry{
		{IP: "5.6.7.8", Timestamp: time.Now(), Path: "/.env", Status: 404, UserAgent: "Mozilla/5.0"},
	}

	scores := s.ScoreEntries(entries)
	sc := scores["5.6.7.8"]
	if sc == nil {
		t.Fatal("no score for IP")
	}
	if sc.Score < 40 {
		t.Errorf("expected score >= 40 for honeypot hit, got %d", sc.Score)
	}
}

func TestScoreScannerUA(t *testing.T) {
	s := newTestScorer()
	entries := []parser.LogEntry{
		{IP: "9.8.7.6", Timestamp: time.Now(), Path: "/", Status: 200, UserAgent: "python-requests/2.28"},
	}

	scores := s.ScoreEntries(entries)
	sc := scores["9.8.7.6"]
	if sc == nil {
		t.Fatal("no score for IP")
	}
	if sc.Score < 20 {
		t.Errorf("expected score >= 20 for scanner UA, got %d", sc.Score)
	}
}

func TestScoreMultiVhost(t *testing.T) {
	s := newTestScorer()
	now := time.Now()

	entries := []parser.LogEntry{
		{IP: "10.0.0.1", Timestamp: now, Path: "/", Status: 200, Domain: "a.com", UserAgent: "Mozilla/5.0"},
		{IP: "10.0.0.1", Timestamp: now, Path: "/", Status: 200, Domain: "b.com", UserAgent: "Mozilla/5.0"},
		{IP: "10.0.0.1", Timestamp: now, Path: "/", Status: 200, Domain: "c.com", UserAgent: "Mozilla/5.0"},
	}

	scores := s.ScoreEntries(entries)
	sc := scores["10.0.0.1"]
	if sc == nil {
		t.Fatal("no score for IP")
	}
	// Should get multi_vhost_scan points (3 domains >= threshold of 3)
	if sc.Score < 15 {
		t.Errorf("expected score >= 15 for multi-vhost, got %d", sc.Score)
	}
}

func TestScoreCombinedTrigger(t *testing.T) {
	s := newTestScorer()
	now := time.Now()

	// Simulate a real scanner: high rate + errors + scanner UA + honeypot
	var entries []parser.LogEntry
	for i := 0; i < 300; i++ {
		entries = append(entries, parser.LogEntry{
			IP:        "198.51.100.7",
			Timestamp: now,
			Path:      "/.env",
			Status:    404,
			UserAgent: "python-requests/2.28",
			Domain:    "example.com",
		})
	}

	scores := s.ScoreEntries(entries)
	sc := scores["198.51.100.7"]
	if sc == nil {
		t.Fatal("no score for IP")
	}
	// Should accumulate: 30 (rate) + 25 (errors) + 20 (UA) + 40 (honeypot) + paths = 115+
	if sc.Score < 60 {
		t.Errorf("expected score >= 60 (block threshold), got %d", sc.Score)
	}
}
