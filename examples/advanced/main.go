// Advanced example: parse template from string, filter, single scan.
package main

import (
	"fmt"

	"github.com/hack007x/veil"
)

func main() {
	// ── Parse template from string ────────────────────────────────────────
	poc := `
## id: demo-version-detect
## name: Version Detection Demo
## author: hack007x
## severity: info
## tags: version, detect

GET /
User-Agent: {{random_ua}}

#@ matcher: status_code == 200
#> extract: name=server, from=headers, kval=Server
#> extract: name=title, regex=/<title>([^<]+)<\/title>/
`

	v := veil.New(veil.DefaultOptions())

	t, err := v.ParseTemplateContent(poc, "inline-demo")
	if err != nil {
		fmt.Printf("Parse error: %v\n", err)
		return
	}
	fmt.Printf("Template: %s (%s)\n\n", t.Metadata.Name, t.Metadata.ID)

	// ── Validate template ─────────────────────────────────────────────────
	report := v.ValidateTemplate(t, poc)
	if report.HasError {
		fmt.Println("Validation errors:")
		report.Print()
		return
	}
	fmt.Println("Template validation passed ✓")

	// ── Scan single target ────────────────────────────────────────────────
	result := v.ScanOne("https://httpbin.org", t)

	fmt.Printf("\nTarget:     %s\n", result.Target)
	fmt.Printf("Vulnerable: %v\n", result.Vulnerable)
	fmt.Printf("MatchedAt:  %s\n", result.MatchedAt)

	if len(result.Extracted) > 0 {
		fmt.Println("Extracted:")
		for k, val := range result.Extracted {
			fmt.Printf("  %s = %s\n", k, val)
		}
	}

	// ── Filtering example ─────────────────────────────────────────────────
	fmt.Println("\n── Filter by severity ──")

	vFiltered := veil.New(veil.Options{
		Timeout:          10,
		FollowRedirects:  true,
		Concurrency:      5,
		FilterSeverities: []string{"critical", "high"},
	})

	templates, _ := vFiltered.LoadTemplates("veil_poc/")
	fmt.Printf("High/Critical templates: %d\n", len(templates))

	// ── Probe only (no scan) ──────────────────────────────────────────────
	fmt.Println("\n── Probe targets ──")
	alive := v.Probe([]string{
		"https://httpbin.org",
		"https://nonexistent.invalid",
		"example.com",
	})
	for _, url := range alive {
		fmt.Printf("  ALIVE: %s\n", url)
	}
}
