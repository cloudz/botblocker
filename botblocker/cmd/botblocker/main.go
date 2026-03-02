package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/botblocker/botblocker/internal/blocker"
	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/logger"
	"github.com/botblocker/botblocker/internal/monitor"
	"github.com/botblocker/botblocker/internal/parser"
	"github.com/botblocker/botblocker/internal/report"
	"github.com/botblocker/botblocker/internal/scorer"
)

const version = "1.1.0"

func main() {
	configPath := flag.String("config", "/usr/local/botblocker/config.ini", "path to config file")
	once := flag.Bool("once", false, "run a single scan cycle and exit (dry-run)")
	scan := flag.Bool("scan", false, "run a single scan cycle, block threats, and exit")
	window := flag.Int("window", 0, "override log_parse_window in seconds (10-86400, requires --once or --scan)")
	showVersion := flag.Bool("version", false, "show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("botblocker v%s\n", version)
		os.Exit(0)
	}

	// Flag validation
	if *once && *scan {
		fmt.Fprintln(os.Stderr, "error: --once and --scan are mutually exclusive")
		os.Exit(1)
	}
	if *window != 0 && !*once && !*scan {
		fmt.Fprintln(os.Stderr, "error: --window requires --once or --scan")
		os.Exit(1)
	}
	if *window != 0 && (*window < 10 || *window > 86400) {
		fmt.Fprintf(os.Stderr, "error: --window must be between 10 and 86400 (got %d)\n", *window)
		os.Exit(1)
	}

	// Load configuration
	cfg, err := config.LoadFromFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Apply window override
	if *window != 0 {
		cfg.LogParseWindow = *window
	}

	if *once {
		runOnce(cfg)
		return
	}
	if *scan {
		runScan(cfg)
		return
	}

	// Daemon mode
	runDaemon(cfg)
}

func runOnce(cfg *config.Config) {
	log := logger.NewStdout(cfg.LogLevel)

	p := parser.New(cfg, log)
	s := scorer.New(cfg, log)

	log.Info("=== BotBlocker v%s — single scan (dry run) ===", version)
	log.Info("parse window: %ds | block threshold: %d", cfg.LogParseWindow, cfg.BlockScore)

	entries, err := p.ParseRecentEntries()
	if err != nil {
		log.Error("parse error: %v", err)
	}

	scores := s.ScoreEntries(entries)
	blockCount := report.PrintReport(os.Stdout, scores, cfg)

	if blockCount > 0 {
		fmt.Println("To block these IPs, run: botblocker --scan")
	}

	log.Info("=== scan complete ===")
}

func runScan(cfg *config.Config) {
	log := logger.NewStdout(cfg.LogLevel)

	p := parser.New(cfg, log)
	s := scorer.New(cfg, log)
	b, err := blocker.New(cfg, log, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	log.Info("=== BotBlocker v%s — SCAN MODE (will block!) ===", version)
	log.Info("parse window: %ds | block threshold: %d", cfg.LogParseWindow, cfg.BlockScore)

	entries, err := p.ParseRecentEntries()
	if err != nil {
		log.Error("parse error: %v", err)
	}

	scores := s.ScoreEntries(entries)
	report.PrintReport(os.Stdout, scores, cfg)

	b.ProcessScores(scores)
	log.Info("=== scan complete ===")
}

func runDaemon(cfg *config.Config) {
	log, err := logger.New(cfg.DaemonLog, cfg.BlockedLog, cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger error: %v\n", err)
		os.Exit(1)
	}
	defer log.Close()

	log.Info("BotBlocker v%s starting — load threshold: %.1f", version, cfg.LoadThreshold())

	p := parser.New(cfg, log)
	s := scorer.New(cfg, log)
	b, err := blocker.New(cfg, log, false)
	if err != nil {
		log.Error("blocker init: %v", err)
		os.Exit(1)
	}

	// Channels
	triggerCh := make(chan string, 1)
	stopCh := make(chan struct{})

	// Start load monitor
	mon := monitor.New(cfg, log)
	go mon.Run(triggerCh, stopCh)

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGUSR1)

	log.Info("daemon running, waiting for triggers...")

	for {
		select {
		case reason := <-triggerCh:
			log.Info("parse cycle triggered (%s), load=%.2f", reason, mon.CurrentLoad())
			runCycle(cfg, p, s, b, log)

		case sig := <-sigCh:
			switch sig {
			case syscall.SIGUSR1:
				log.Info("SIGUSR1 received — forcing immediate scan")
				runCycle(cfg, p, s, b, log)
			case syscall.SIGTERM, syscall.SIGINT:
				log.Info("received %s, shutting down", sig)
				close(stopCh)
				return
			}
		}
	}
}

func runCycle(cfg *config.Config, p *parser.Parser, s *scorer.Scorer, b *blocker.Blocker, log *logger.Logger) {
	entries, err := p.ParseRecentEntries()
	if err != nil {
		log.Error("parse error: %v", err)
		return
	}

	if len(entries) == 0 {
		log.Debug("no log entries in window, nothing to score")
		return
	}

	scores := s.ScoreEntries(entries)

	// Count how many are above threshold
	above := 0
	for _, sc := range scores {
		if sc.Score >= cfg.BlockScore {
			above++
		}
	}
	log.Info("scored %d IPs, %d above block threshold", len(scores), above)

	b.ProcessScores(scores)
}
