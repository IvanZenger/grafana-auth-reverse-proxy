// Package cmd contains the command-line interface structure and handling for the Grafana Auth Reverse Proxy application.
// It defines the root command structure 'Cli', along with global flags and options that can be set through the command line or environment variables.
// The package utilizes the 'king' library to handle version information and provides a structured way to define and parse CLI commands and arguments.
//
// The 'Cli' struct acts as the root for all CLI commands, encapsulating command-specific options and global settings.
// The 'Globals' struct contains global command-line arguments or environment variables, such as debug flags and version information.
package cmd

import (
	"github.com/zbindenren/king"
)

// Cli serves as the root structure for command-line argument parsing. It combines the specific commands
// like 'Run' with global configurations encapsulated in the 'Globals' struct.
// Use this struct to define and access command-specific options as well as global settings.
type Cli struct {
	Run     Run `cmd:"" help:"Start the Grafana Auth Reverse Proxy server with the specified configurations."`
	Globals `envprefix:"GLOBALS_" help:"Global configurations applicable across all commands."`
}

// Globals defines global configuration options available for all commands in the CLI.
// It includes settings such as the debug level and version information.
// These settings can be set via environment variables or command-line flags.
type Globals struct {
	Debug   bool             `default:"false" env:"DEBUG" help:"Set debug log level. Defaults to 'false'."`
	Version king.VersionFlag `env:"VERSION" help:"Show version information and exit."`
}
