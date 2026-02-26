package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/server"
)

var version = "dev" // set by goreleaser ldflags

func main() {
	showVersion := flag.Bool("version", false, "Print version and exit")
	debugMode := flag.Bool("debug", false, "Enable debug logging to stderr")
	flag.Parse()

	if *showVersion {
		fmt.Println("aguara-mcp", version)
		os.Exit(0)
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

	RegisterTools(s, *debugMode)

	// Serve via stdio.
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
