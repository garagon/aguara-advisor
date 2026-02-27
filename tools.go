package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/garagon/aguara"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const scanTimeout = 30 * time.Second

const maxContentSize = 10 << 20 // 10 MB

var validRuleID = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

// RegisterTools registers all aguara tools on the MCP server.
func RegisterTools(s *mcp.Server, debug bool) {
	s.AddTool(scanContentTool(), handleScanContent(debug))
	s.AddTool(checkMCPConfigTool(), handleCheckMCPConfig(debug))
	s.AddTool(listRulesTool(), handleListRules())
	s.AddTool(explainRuleTool(), handleExplainRule())
}

// --- Tool definitions ---

func boolPtr(b bool) *bool { return &b }

func prop(typ, desc string) map[string]any {
	return map[string]any{"type": typ, "description": desc}
}

func scanContentTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "scan_content",
		Description: "Scan the content of an AI agent skill or MCP server description for security issues. " +
			"Checks for prompt injection, credential leaks, exfiltration, command execution, and more.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"content":  prop("string", "The text content to scan (e.g., skill description, README, tool definition)"),
				"filename": prop("string", "Filename hint for the content (affects rule matching). Default: skill.md"),
			},
			"required": []string{"content"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func checkMCPConfigTool() *mcp.Tool {
	return &mcp.Tool{
		Name: "check_mcp_config",
		Description: "Check an MCP server configuration (JSON) for security issues. " +
			"Detects dangerous command patterns, credential exposure, and unsafe settings.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"config": prop("string", "The MCP configuration as a JSON string"),
			},
			"required": []string{"config"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func listRulesTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "list_rules",
		Description: "List available security rules. Optionally filter by category.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"category": prop("string", "Filter rules by category (e.g., prompt-injection, exfiltration, credential-leak)"),
			},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

func explainRuleTool() *mcp.Tool {
	return &mcp.Tool{
		Name:        "explain_rule",
		Description: "Get detailed information about a specific security rule, including its patterns and examples.",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"rule_id": prop("string", "The rule ID to explain (e.g., PROMPT_INJECTION_001)"),
			},
			"required": []string{"rule_id"},
		},
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			DestructiveHint: boolPtr(false),
			OpenWorldHint:   boolPtr(false),
		},
	}
}

// --- Argument helpers ---

func getString(raw json.RawMessage, key, defaultVal string) string {
	if len(raw) == 0 {
		return defaultVal
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return defaultVal
	}
	v, ok := m[key]
	if !ok {
		return defaultVal
	}
	s, ok := v.(string)
	if !ok {
		return defaultVal
	}
	return s
}

func newToolResultText(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
	}
}

func newToolResultError(msg string) *mcp.CallToolResult {
	var r mcp.CallToolResult
	r.SetError(fmt.Errorf("%s", msg))
	return &r
}

// --- Tool handlers ---

func handleScanContent(debug bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		content := getString(req.Params.Arguments, "content", "")
		if content == "" {
			return newToolResultError("content parameter is required"), nil
		}
		if len(content) > maxContentSize {
			return newToolResultError(fmt.Sprintf("content too large: %d bytes (max %d)", len(content), maxContentSize)), nil
		}

		filename := getString(req.Params.Arguments, "filename", "skill.md")
		filename = sanitizeFilename(filename)

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan_content: file=%s len=%d\n", filename, len(content))
		}

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, scanTimeout)
			defer cancel()
		}

		result, err := aguara.ScanContent(ctx, content, filename)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] scan_content error: %v\n", err)
			}
			return newToolResultError("scan failed"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan result: %d findings\n", len(result.Findings))
		}

		return newToolResultText(formatScanResult(result)), nil
	}
}

func handleCheckMCPConfig(debug bool) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		config := getString(req.Params.Arguments, "config", "")
		if config == "" {
			return newToolResultError("config parameter is required"), nil
		}
		if len(config) > maxContentSize {
			return newToolResultError(fmt.Sprintf("config too large: %d bytes (max %d)", len(config), maxContentSize)), nil
		}

		// Validate it's valid JSON.
		if !json.Valid([]byte(config)) {
			return newToolResultError("config is not valid JSON"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] check_mcp_config: len=%d\n", len(config))
		}

		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, scanTimeout)
			defer cancel()
		}

		result, err := aguara.ScanContent(ctx, config, "config.json")
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] check_mcp_config error: %v\n", err)
			}
			return newToolResultError("scan failed"), nil
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] scan result: %d findings\n", len(result.Findings))
		}

		return newToolResultText(formatScanResult(result)), nil
	}
}

func handleListRules() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		category := getString(req.Params.Arguments, "category", "")

		var opts []aguara.Option
		if category != "" {
			opts = append(opts, aguara.WithCategory(category))
		}

		rules := aguara.ListRules(opts...)

		out, err := json.MarshalIndent(rules, "", "  ")
		if err != nil {
			return newToolResultError("failed to format rules"), nil
		}

		return newToolResultText(string(out)), nil
	}
}

func handleExplainRule() mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		ruleID := getString(req.Params.Arguments, "rule_id", "")
		if ruleID == "" {
			return newToolResultError("rule_id parameter is required"), nil
		}
		if !validRuleID.MatchString(ruleID) {
			return newToolResultError("invalid rule_id format: must match [A-Z][A-Z0-9_]+ (e.g., PROMPT_INJECTION_001)"), nil
		}

		detail, err := aguara.ExplainRule(ruleID)
		if err != nil {
			return newToolResultError(fmt.Sprintf("rule %s not found", ruleID)), nil
		}

		out, err := json.MarshalIndent(detail, "", "  ")
		if err != nil {
			return newToolResultError("failed to format rule info"), nil
		}

		return newToolResultText(string(out)), nil
	}
}

// --- Formatting helpers ---

// formatScanResult produces a structured JSON response for scan results.
func formatScanResult(result *aguara.ScanResult) string {
	type findingOut struct {
		Severity    string  `json:"severity"`
		RuleID      string  `json:"rule_id"`
		Category    string  `json:"category"`
		RuleName    string  `json:"rule_name"`
		Description string  `json:"description"`
		Line        int     `json:"line"`
		MatchedText string  `json:"matched_text"`
		InCodeBlock bool    `json:"in_code_block"`
		Score       float64 `json:"score"`
	}

	type statsOut struct {
		FilesScanned int `json:"files_scanned"`
		RulesLoaded  int `json:"rules_loaded"`
	}

	type response struct {
		Summary  string       `json:"summary"`
		Findings []findingOut `json:"findings"`
		Stats    statsOut     `json:"stats"`
	}

	findings := make([]findingOut, 0, len(result.Findings))
	counts := make(map[string]int)

	for _, f := range result.Findings {
		sevName := f.Severity.String()
		counts[sevName]++
		findings = append(findings, findingOut{
			Severity:    sevName,
			RuleID:      f.RuleID,
			Category:    f.Category,
			RuleName:    f.RuleName,
			Description: f.Description,
			Line:        f.Line,
			MatchedText: f.MatchedText,
			InCodeBlock: f.InCodeBlock,
			Score:       f.Score,
		})
	}

	resp := response{
		Summary:  formatSummary(len(result.Findings), counts),
		Findings: findings,
		Stats: statsOut{
			FilesScanned: result.FilesScanned,
			RulesLoaded:  result.RulesLoaded,
		},
	}

	out, _ := json.MarshalIndent(resp, "", "  ")
	return string(out)
}

// formatSummary creates a human-readable summary like "Found 3 issues: 1 critical, 2 high".
func formatSummary(total int, counts map[string]int) string {
	if total == 0 {
		return "No security issues found."
	}

	var parts []string
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if n, ok := counts[sev]; ok && n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(sev)))
		}
	}

	issue := "issue"
	if total != 1 {
		issue = "issues"
	}

	return fmt.Sprintf("Found %d %s: %s", total, issue, strings.Join(parts, ", "))
}

var safeFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

// sanitizeFilename strips path components, restricts to safe characters, and caps length.
func sanitizeFilename(name string) string {
	// Remove any directory components.
	i := strings.LastIndexAny(name, `/\`)
	if i >= 0 {
		name = name[i+1:]
	}
	// Remove leading dots to prevent hidden files.
	name = strings.TrimLeft(name, ".")
	// Strip any characters outside the allowlist.
	name = safeFilenameChars.ReplaceAllString(name, "")
	if name == "" {
		return "skill.md"
	}
	// Cap length to prevent excessively long filenames.
	if len(name) > 64 {
		name = name[:64]
	}
	return name
}
