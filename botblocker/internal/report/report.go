package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/botblocker/botblocker/internal/config"
	"github.com/botblocker/botblocker/internal/scorer"
)

// PrintReport prints a sorted table of all scored IPs and returns the count
// of IPs above the block threshold.
func PrintReport(w io.Writer, scores map[string]*scorer.IPScore, cfg *config.Config) int {
	// Collect IPs with score > 0
	var items []*scorer.IPScore
	for _, sc := range scores {
		if sc.Score > 0 {
			items = append(items, sc)
		}
	}

	if len(items) == 0 {
		fmt.Fprintln(w, "No suspicious IPs found.")
		return 0
	}

	// Sort descending by score, then ascending by IP for stability
	sort.Slice(items, func(i, j int) bool {
		if items[i].Score != items[j].Score {
			return items[i].Score > items[j].Score
		}
		return items[i].IP < items[j].IP
	})

	// Print header
	fmt.Fprintf(w, "\n%-4s %-18s %5s %6s %7s %5s %7s  %s\n",
		"", "IP", "SCORE", "REQS", "REQ/MIN", "ERR%", "DOMAINS", "REASONS")
	fmt.Fprintln(w, strings.Repeat("-", 90))

	blockCount := 0
	for _, sc := range items {
		marker := "  "
		if sc.Score >= cfg.BlockScore {
			marker = ">>"
			blockCount++
		}

		reasons := strings.Join(sc.Reasons, "; ")

		fmt.Fprintf(w, "%-4s %-18s %5d %6d %7.0f %4.0f%% %7d  %s\n",
			marker, sc.IP, sc.Score, sc.TotalRequests,
			sc.RequestsPerMin, sc.ErrorRate, len(sc.Domains), reasons)
	}

	fmt.Fprintln(w, strings.Repeat("-", 90))
	fmt.Fprintf(w, "Total: %d scored, %d above block threshold (%d)\n\n",
		len(items), blockCount, cfg.BlockScore)

	return blockCount
}
