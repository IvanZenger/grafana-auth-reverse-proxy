package main

import (
	"github.com/alecthomas/kong"
	"github.com/postfinance/flash"
	"github.com/zbindenren/king"
	"gitlab.pnet.ch/observability/grafana/grafana-auth-reverse-proxy/cmd"
	"os"
)

var (
	version = "1.0.0"
	commit  = "99999999"
	date    = "2020-09-22T11:11:10+02:00"
)

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
