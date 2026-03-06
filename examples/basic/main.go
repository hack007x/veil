// Basic example: scan a single target with templates from a directory.
package main

import (
	"fmt"
	"os"

	"github.com/hack007x/veil"
)

func main() {
	// Create scanner with default options
	v := veil.New(veil.Options{
		Timeout:         10,
		FollowRedirects: true,
		Concurrency:     5,
	})

	fmt.Printf("Engine: %s  Version: %s\n\n", v.EngineName(), v.EngineVersion())

	// Load templates from directory
	templates, err := v.LoadTemplates("veil_poc/")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load templates: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Loaded %d templates\n", len(templates))

	// Scan with real-time callback
	targets := []string{"https://example.com"}
	results := v.Scan(targets, templates, func(r *veil.ScanResult, done, total int) {
		if r.Vulnerable {
			fmt.Printf("[VULN] %s  %s  %s\n", r.TemplateID, r.Severity, r.MatchedAt)
		}
		if done%10 == 0 || done == total {
			fmt.Printf("  Progress: %d/%d\n", done, total)
		}
	})

	// Summary
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}
	fmt.Printf("\nDone. %d vulnerabilities found out of %d scans.\n", vulnCount, len(results))

	// Save report
	if vulnCount > 0 {
		_ = v.SaveJSON(results, "results.json")
		_ = v.SaveHTML(results, "report.html")
		fmt.Println("Reports saved: results.json, report.html")
	}
}
