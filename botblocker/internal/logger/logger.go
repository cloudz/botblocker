package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG",
	INFO:  "INFO",
	WARN:  "WARN",
	ERROR: "ERROR",
}

// Logger provides structured logging for the daemon.
type Logger struct {
	mu         sync.Mutex
	daemonFile *os.File
	blockFile  *os.File
	level      Level
	stdout     bool // also log to stdout
}

// New creates a new logger writing to the given log files.
func New(daemonLogPath, blockLogPath, levelStr string) (*Logger, error) {
	level := parseLevel(levelStr)

	if err := os.MkdirAll(filepath.Dir(daemonLogPath), 0750); err != nil {
		return nil, fmt.Errorf("create daemon log dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(blockLogPath), 0750); err != nil {
		return nil, fmt.Errorf("create block log dir: %w", err)
	}

	// Open with restrictive permissions: owner read/write only
	df, err := os.OpenFile(daemonLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open daemon log: %w", err)
	}

	bf, err := os.OpenFile(blockLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		df.Close()
		return nil, fmt.Errorf("open block log: %w", err)
	}

	return &Logger{
		daemonFile: df,
		blockFile:  bf,
		level:      level,
		stdout:     false,
	}, nil
}

// NewStdout creates a logger that writes to stdout only (for --once mode).
func NewStdout(levelStr string) *Logger {
	return &Logger{
		level:  parseLevel(levelStr),
		stdout: true,
	}
}

// SetStdout enables or disables additional stdout output alongside file logging.
func (l *Logger) SetStdout(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stdout = enabled
}

// Close closes all log files.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.daemonFile != nil {
		l.daemonFile.Close()
	}
	if l.blockFile != nil {
		l.blockFile.Close()
	}
}

func (l *Logger) Debug(format string, args ...interface{}) { l.log(DEBUG, format, args...) }
func (l *Logger) Info(format string, args ...interface{})  { l.log(INFO, format, args...) }
func (l *Logger) Warn(format string, args ...interface{})  { l.log(WARN, format, args...) }
func (l *Logger) Error(format string, args ...interface{}) { l.log(ERROR, format, args...) }

func (l *Logger) log(level Level, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	msg := fmt.Sprintf(format, args...)
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] %s %s\n", ts, levelNames[level], msg)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.stdout {
		fmt.Print(line)
	}
	if l.daemonFile != nil {
		l.daemonFile.WriteString(line)
	}
}

// Block writes a structured block event to the block log.
func (l *Logger) Block(action, blockType, ip string, score int, ttl string, reason string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] ACTION=%s TYPE=%s IP=%s SCORE=%d TTL=%s REASON=%q\n",
		ts, action, blockType, ip, score, ttl, reason)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.stdout {
		fmt.Print(line)
	}
	if l.blockFile != nil {
		l.blockFile.WriteString(line)
	}
	if l.daemonFile != nil {
		l.daemonFile.WriteString(line)
	}
}

// Unblock writes an unblock event to the block log.
func (l *Logger) Unblock(ip string) {
	ts := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("[%s] ACTION=UNBLOCK IP=%s\n", ts, ip)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.stdout {
		fmt.Print(line)
	}
	if l.blockFile != nil {
		l.blockFile.WriteString(line)
	}
}

func parseLevel(s string) Level {
	switch s {
	case "debug":
		return DEBUG
	case "warn":
		return WARN
	case "error":
		return ERROR
	default:
		return INFO
	}
}
