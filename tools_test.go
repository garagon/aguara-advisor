package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/garagon/aguara"
)

func TestFormatSummaryNoFindings(t *testing.T) {
	got := formatSummary(0, nil)
	want := "No security issues found."
	if got != want {
		t.Errorf("formatSummary(0, nil) = %q, want %q", got, want)
	}
}

func TestFormatSummarySingleFinding(t *testing.T) {
	counts := map[string]int{"CRITICAL": 1}
	got := formatSummary(1, counts)
	want := "Found 1 issue: 1 critical"
	if got != want {
		t.Errorf("formatSummary(1, ...) = %q, want %q", got, want)
	}
}

func TestFormatSummaryMultipleFindings(t *testing.T) {
	counts := map[string]int{"CRITICAL": 1, "HIGH": 2, "LOW": 1}
	got := formatSummary(4, counts)
	want := "Found 4 issues: 1 critical, 2 high, 1 low"
	if got != want {
		t.Errorf("formatSummary(4, ...) = %q, want %q", got, want)
	}
}

func TestFormatScanResultNoFindings(t *testing.T) {
	result := &aguara.ScanResult{
		FilesScanned: 1,
		RulesLoaded:  138,
	}

	out := formatScanResult(result)

	var resp struct {
		Summary  string          `json:"summary"`
		Findings json.RawMessage `json:"findings"`
		Stats    struct {
			FilesScanned int `json:"files_scanned"`
			RulesLoaded  int `json:"rules_loaded"`
		} `json:"stats"`
	}

	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	if resp.Summary != "No security issues found." {
		t.Errorf("summary = %q, want no issues", resp.Summary)
	}
	if resp.Stats.FilesScanned != 1 {
		t.Errorf("files_scanned = %d, want 1", resp.Stats.FilesScanned)
	}
	if resp.Stats.RulesLoaded != 138 {
		t.Errorf("rules_loaded = %d, want 138", resp.Stats.RulesLoaded)
	}
}

func TestFormatScanResultWithFindings(t *testing.T) {
	result := &aguara.ScanResult{
		Findings: []aguara.Finding{
			{
				RuleID:      "PROMPT_INJECTION_001",
				RuleName:    "Instruction override attempt",
				Severity:    aguara.SeverityCritical,
				Category:    "prompt-injection",
				Description: "Detects attempts to override instructions",
				Line:        5,
				MatchedText: "Ignore all previous instructions",
				Score:       52,
			},
			{
				RuleID:      "EXFIL_001",
				RuleName:    "Data exfiltration URL",
				Severity:    aguara.SeverityHigh,
				Category:    "exfiltration",
				Description: "Detects exfiltration URLs",
				Line:        10,
				MatchedText: "https://evil.com/collect",
				Score:       40,
			},
		},
		FilesScanned: 1,
		RulesLoaded:  138,
	}

	out := formatScanResult(result)

	var resp struct {
		Summary  string `json:"summary"`
		Findings []struct {
			Severity string `json:"severity"`
			RuleID   string `json:"rule_id"`
		} `json:"findings"`
	}

	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		t.Fatalf("failed to parse output: %v", err)
	}

	if len(resp.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(resp.Findings))
	}

	if resp.Findings[0].Severity != "CRITICAL" {
		t.Errorf("finding[0].severity = %q, want CRITICAL", resp.Findings[0].Severity)
	}
	if resp.Findings[1].Severity != "HIGH" {
		t.Errorf("finding[1].severity = %q, want HIGH", resp.Findings[1].Severity)
	}
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"skill.md", "skill.md"},
		{"../../../etc/passwd", "passwd"},
		{".hidden", "hidden"},
		{"...", "skill.md"},
		{"", "skill.md"},
		{"path/to/file.json", "file.json"},
		{`C:\Users\test\file.md`, "file.md"},
		{"normal-name.txt", "normal-name.txt"},
		{"file with spaces.md", "filewithspaces.md"},
		{"evil*glob?.md", "evilglob.md"},
		{"null\x00byte.md", "nullbyte.md"},
		{strings.Repeat("a", 100) + ".md", strings.Repeat("a", 64)},
	}

	for _, tt := range tests {
		got := sanitizeFilename(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestValidRuleID(t *testing.T) {
	valid := []string{"PROMPT_INJECTION_001", "EXFIL_007", "CRED_001", "A1", "NLP_PROMPT_INJECTION"}
	for _, id := range valid {
		if !validRuleID.MatchString(id) {
			t.Errorf("expected %q to be valid", id)
		}
	}

	invalid := []string{"--help", "-v", "", "lower_case", "A", "123", "RULE;DROP", "../etc", "--format yaml"}
	for _, id := range invalid {
		if validRuleID.MatchString(id) {
			t.Errorf("expected %q to be invalid", id)
		}
	}
}
