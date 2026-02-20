package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/mark3labs/mcp-go/server"
)

const version = "0.1.0"

func main() {
	aguaraPath := flag.String("aguara-path", "", "Path to aguara binary (default: search PATH)")
	showVersion := flag.Bool("version", false, "Print version and exit")
	debugMode := flag.Bool("debug", false, "Enable debug logging to stderr")
	flag.Parse()

	if *showVersion {
		fmt.Println("aguara-mcp", version)
		os.Exit(0)
	}

	// Find the aguara binary.
	binPath := *aguaraPath
	if binPath == "" {
		var err error
		binPath, err = exec.LookPath("aguara")
		if err != nil {
			log.Fatal("aguara binary not found in PATH. Install aguara or use --aguara-path flag.")
		}
	}

	runner, err := NewRunner(binPath)
	if err != nil {
		log.Fatalf("Failed to initialize aguara runner: %v", err)
	}

	// Create MCP server.
	s := server.NewMCPServer(
		"aguara",
		version,
		server.WithToolCapabilities(false),
		server.WithInstructions(
			"Aguara is a security scanner for AI agent skills and MCP servers. "+
				"Use these tools to check skill descriptions, MCP configurations, "+
				"and tool definitions for security issues before installing or using them.",
		),
	)

	RegisterTools(s, runner, *debugMode)

	// Serve via stdio.
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
