package parser

import (
	"testing"

	"github.com/botblocker/botblocker/internal/config"
)

func newTestParser() *Parser {
	cfg := config.DefaultConfig()
	return &Parser{cfg: cfg}
}

func TestParseLineValid(t *testing.T) {
	p := newTestParser()
	line := `203.0.113.42 - - [25/Jan/2024:14:32:10 +0000] "GET /wp-login.php HTTP/1.1" 404 1234 "-" "python-requests/2.28"`

	entry, ok := p.parseLine(line, "example.com")
	if !ok {
		t.Fatal("expected successful parse")
	}
	if entry.IP != "203.0.113.42" {
		t.Errorf("IP = %s, want 203.0.113.42", entry.IP)
	}
	if entry.Status != 404 {
		t.Errorf("Status = %d, want 404", entry.Status)
	}
	if entry.Path != "/wp-login.php" {
		t.Errorf("Path = %s, want /wp-login.php", entry.Path)
	}
	if entry.UserAgent != "python-requests/2.28" {
		t.Errorf("UA = %s", entry.UserAgent)
	}
	if entry.Domain != "example.com" {
		t.Errorf("Domain = %s", entry.Domain)
	}
}

func TestParseLineInvalidIP(t *testing.T) {
	p := newTestParser()
	// Crafted log line with command injection in IP field
	line := `1.2.3.4;rm%20-rf%20/ - - [25/Jan/2024:14:32:10 +0000] "GET / HTTP/1.1" 200 0 "-" "curl"`

	_, ok := p.parseLine(line, "")
	if ok {
		t.Error("should reject line with invalid IP")
	}
}

func TestParseLineMalformed(t *testing.T) {
	p := newTestParser()
	cases := []string{
		"",
		"garbage data that is not a log line",
		"1.2.3.4",
		`1.2.3.4 - - [INVALID-DATE] "GET / HTTP/1.1" 200 0 "-" "ua"`,
	}
	for _, line := range cases {
		if _, ok := p.parseLine(line, ""); ok {
			t.Errorf("should not parse: %q", line)
		}
	}
}

func TestSanitize(t *testing.T) {
	// Control character stripping (log injection prevention)
	got := sanitize("normal\x00\x01\x1f\x7ftext", 100)
	if got != "normaltext" {
		t.Errorf("sanitize didn't strip control chars: %q", got)
	}

	// Truncation
	got = sanitize("abcdefghij", 5)
	if got != "abcde" {
		t.Errorf("sanitize truncation: %q", got)
	}
}
