/*
Package main is the entry point of the Grafana Auth Reverse Proxy application. This application provides a reverse proxy for authenticating users and forwarding requests to Grafana with appropriate authentication headers.

It utilizes Kong for command-line parsing and configuration management, enabling developers to easily configure and deploy the reverse proxy with various authentication options.

The main function initializes the application, parses command-line arguments, sets up logging, and starts the server to listen for incoming requests.

Usage:

	To run the Grafana Auth Reverse Proxy application, use the following command:
	    $ ./grafana-auth-reverse-proxy [flags]

Flags:

	--help                      Show help for the command
	--version                   Show the version information for the command
	--debug                     Enable debug mode for logging
	--config-file FILE          Specify the path to the configuration file (default: "config.yaml")

Environment Variables:

	GLOBALS_DEBUG               Set to "true" to enable debug mode for logging
	GLOBALS_VERSION             Show version information

Example:

	$ ./grafana-auth-reverse-proxy --config-file=config.yaml

For more information on available flags and configuration options, refer to the documentation or the README.md file.
*/
package main

import (
	"os"

	"github.com/alecthomas/kong"
	"github.com/postfinance/flash"
	"github.com/zbindenren/king"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/cmd"
)

//nolint:gochecknoglobals // these variables are set by goreleaser
var (
	version = "1.0.0"
	commit  = "99999999"
	date    = "2020-09-22T11:11:10+02:00"
)

// The main function is the entry point of the Grafana Auth Reverse Proxy application.
// It initializes the command-line interface parameters, configures logging, and parses the CLI arguments.
// The application version, commit hash, and build date are set up using king library for displaying build information.
// The Kong library is used for CLI parsing and handling. If any errors occur during the CLI parsing or application run,
// the program logs the error and exits with a non-zero status.
func main() {
	cli := cmd.Cli{}
	l := flash.New(flash.WithColor(), flash.WithDebug(cli.Globals.Debug))

	b, err := king.NewBuildInfo(version,
		king.WithDateString(date),
		king.WithRevision(commit),
		king.WithLocation("Europe/Zurich"),
	)
	if err != nil {
		l.Fatal(err)
	}

	app := kong.Parse(&cli, king.DefaultOptions(
		king.Config{
			Name:        "grafana-auth-reverse-proxy",
			Description: "",
			BuildInfo:   b,
		},
	)...)

	l.SetDebug(cli.Debug)

	if err := app.Run(&cli.Globals, l.Get()); err != nil {
		l.Fatal(err)
		os.Exit(1)
	}

	os.Exit(0)
}
