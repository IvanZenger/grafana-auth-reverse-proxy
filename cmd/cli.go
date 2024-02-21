package cmd

import (
	"github.com/zbindenren/king"
)

// Cli is the root struct
type Cli struct {
	Run     Run `cmd:""`
	Globals `envprefix:"GLOBALS_"`
}

// Globals contains global command arguments
type Globals struct {
	Debug   bool             `default:"false" env:"DEBUG" help:"Set debug log level."`
	Version king.VersionFlag `env:"VERSION" help:"Show version information"`
}
