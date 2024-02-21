package cmd

import (
	"github.com/zbindenren/king"
)

// Cli is the root struct
type Cli struct {
	Run Run `cmd:"" help:"Execute specific OpenSearch jobs as defined in the configuration. Use this command to initiate predefined tasks or processes within OpenSearch."`
	Globals
}

// Globals contains global command arguments
type Globals struct {
	Debug   bool             `default:"false" env:"OPENSEARCH_CLI_GLOBALS_DEBUG" help:"Set debug log level."`
	Version king.VersionFlag `env:"GLOBALS_VERSION" help:"Show version information"`
}
