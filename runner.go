package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

const maxStderr = 4096 // Cap stderr capture to prevent memory exhaustion.

const cmdTimeout = 30 * time.Second

// Runner executes aguara CLI commands as subprocesses.
type Runner struct {
	binaryPath string
}

// NewRunner creates a Runner after validating that the aguara binary exists and works.
func NewRunner(path string) (*Runner, error) {
	if path == "" {
		return nil, fmt.Errorf("aguara binary path is empty")
	}

	// Verify the binary exists and is executable.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, "version")
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("aguara binary not usable at %q: %w", path, err)
	}

	return &Runner{binaryPath: path}, nil
}

// Scan runs `aguara scan <filePath> --format json` and returns parsed results.
// Exit code 1 is expected when findings are present — the JSON output is still valid.
func (r *Runner) Scan(ctx context.Context, filePath string) (*ScanResult, error) {
	stdout, err := r.run(ctx, "scan", filePath, "--format", "json")
	if err != nil {
		// aguara exits 1 when findings are found; check if we got valid JSON anyway.
		if len(stdout) == 0 {
			return nil, fmt.Errorf("aguara scan failed: %w", err)
		}
	}

	var result ScanResult
	if err := json.Unmarshal(stdout, &result); err != nil {
		return nil, fmt.Errorf("failed to parse scan output: %w", err)
	}
	return &result, nil
}

// ListRules runs `aguara list-rules --format json` and returns the rule list.
func (r *Runner) ListRules(ctx context.Context) ([]RuleInfo, error) {
	stdout, err := r.run(ctx, "list-rules", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("aguara list-rules failed: %w", err)
	}

	var rules []RuleInfo
	if err := json.Unmarshal(stdout, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse list-rules output: %w", err)
	}
	return rules, nil
}

// ExplainRule runs `aguara explain <ruleID> --format json` and returns rule details.
func (r *Runner) ExplainRule(ctx context.Context, ruleID string) (*ExplainInfo, error) {
	stdout, err := r.run(ctx, "explain", ruleID, "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("aguara explain failed: %w", err)
	}

	var info ExplainInfo
	if err := json.Unmarshal(stdout, &info); err != nil {
		return nil, fmt.Errorf("failed to parse explain output: %w", err)
	}
	return &info, nil
}

// run executes the aguara binary with the given arguments and returns stdout.
func (r *Runner) run(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, cmdTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, r.binaryPath, args...)

	var stdout bytes.Buffer
	stderr := &limitedBuffer{max: maxStderr}
	cmd.Stdout = &stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	if err != nil {
		// Return stdout even on error — aguara writes valid JSON on exit code 1.
		return stdout.Bytes(), fmt.Errorf("%w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// limitedBuffer is a bytes.Buffer that silently drops writes beyond max bytes.
type limitedBuffer struct {
	buf bytes.Buffer
	max int
}

func (lb *limitedBuffer) Write(p []byte) (int, error) {
	remaining := lb.max - lb.buf.Len()
	if remaining <= 0 {
		return len(p), nil // Discard silently.
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	lb.buf.Write(p)
	return len(p), nil
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}
