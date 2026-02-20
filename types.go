package main

// ScanResult matches the JSON output of `aguara scan --format json`.
type ScanResult struct {
	Findings     []Finding `json:"findings"`
	FilesScanned int       `json:"files_scanned"`
	RulesLoaded  int       `json:"rules_loaded"`
	DurationMS   int64     `json:"duration_ms"`
}

// Finding represents a single security finding from a scan.
type Finding struct {
	RuleID      string  `json:"rule_id"`
	RuleName    string  `json:"rule_name"`
	Severity    int     `json:"severity"`
	Category    string  `json:"category"`
	Description string  `json:"description"`
	FilePath    string  `json:"file_path"`
	Line        int     `json:"line"`
	MatchedText string  `json:"matched_text"`
	InCodeBlock bool    `json:"in_code_block"`
	Score       float64 `json:"score"`
	Analyzer    string  `json:"analyzer"`
}

// RuleInfo matches the JSON output of `aguara list-rules --format json`.
type RuleInfo struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

// ExplainInfo matches the JSON output of `aguara explain <id> --format json`.
type ExplainInfo struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	Description    string   `json:"description"`
	Patterns       []string `json:"patterns"`
	TruePositives  []string `json:"true_positives"`
	FalsePositives []string `json:"false_positives"`
}

// SeverityName converts a numeric severity (0-4) to its string name.
func SeverityName(sev int) string {
	switch sev {
	case 0:
		return "INFO"
	case 1:
		return "LOW"
	case 2:
		return "MEDIUM"
	case 3:
		return "HIGH"
	case 4:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
