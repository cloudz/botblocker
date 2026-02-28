package blocker

import (
	"testing"
)

func TestIsValidIP(t *testing.T) {
	valid := []string{
		"1.2.3.4",
		"192.168.1.1",
		"255.255.255.255",
		"0.0.0.0",
		"::1",
		"2001:db8::1",
		"fe80::1",
	}
	for _, ip := range valid {
		if !isValidIP(ip) {
			t.Errorf("expected valid: %s", ip)
		}
	}

	invalid := []string{
		"",
		"not-an-ip",
		"1.2.3.4; rm -rf /",         // command injection
		"1.2.3.4\nX-Injected: true", // header injection
		"1.2.3.4$(whoami)",           // shell expansion
		"1.2.3.4`whoami`",            // backtick injection
		"1.2.3.4|cat /etc/passwd",    // pipe injection
		"999.999.999.999",            // invalid octets
		"../../../etc/passwd",        // path traversal
		"1.2.3.4 ",                   // trailing space
		" 1.2.3.4",                   // leading space
	}
	for _, ip := range invalid {
		if isValidIP(ip) {
			t.Errorf("expected invalid: %q", ip)
		}
	}
}

func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"normal text", "normal text"},
		{"has\nnewline", "has?newline"},
		{"has\x00null", "has?null"},
		{"has\ttab", "has?tab"},
	}
	for _, tc := range tests {
		got := sanitizeForLog(tc.input)
		if got != tc.expected {
			t.Errorf("sanitizeForLog(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}

	// Test truncation
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'A'
	}
	got := sanitizeForLog(string(long))
	if len(got) > 100 {
		t.Errorf("sanitizeForLog should truncate to 100 chars, got %d", len(got))
	}
}
