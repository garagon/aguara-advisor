package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
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
	s := mcp.NewServer(&mcp.Implementation{
		Name:    "aguara",
		Version: version,
	}, &mcp.ServerOptions{
		Instructions: "Aguara is a security scanner for AI agent skills and MCP servers. " +
			"Use these tools to check skill descriptions, MCP configurations, " +
			"and tool definitions for security issues before installing or using them.",
	})

	RegisterTools(s, *debugMode)

	// Serve via stdio.
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
