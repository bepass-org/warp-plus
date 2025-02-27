package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/bepass-org/warp-plus/ipscanner"
	"github.com/bepass-org/warp-plus/warp"
	"github.com/carlmjohnson/versioninfo"
	"github.com/fatih/color"
	"github.com/peterbourgon/ff/v4"
	"github.com/peterbourgon/ff/v4/ffhelp"
	"github.com/rodaine/table"
)

const appName = "warp-scan"

var version string = ""

func main() {
	fs := ff.NewFlagSet(appName)
	var (
		v4      = fs.BoolShort('4', "only use IPv4 for random warp endpoint")
		v6      = fs.BoolShort('6', "only use IPv6 for random warp endpoint")
		rtt     = fs.DurationLong("rtt", 1000*time.Millisecond, "scanner rtt limit")
		verFlag = fs.BoolLong("version", "displays version number")
	)

	err := ff.Parse(fs, os.Args[1:])
	switch {
	case errors.Is(err, ff.ErrHelp):
		fmt.Fprintf(os.Stderr, "%s\n", ffhelp.Flags(fs))
		os.Exit(0)
	case err != nil:
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *verFlag {
		if version == "" {
			version = versioninfo.Short()
		}
		fmt.Fprintf(os.Stderr, "%s\n", version)
		os.Exit(0)
	}

	// Essentially doing XNOR to make sure that if they are both false
	// or both true, just set them both true.
	if *v4 == *v6 {
		*v4, *v6 = true, true
	}

	// new scanner
	scanner := ipscanner.NewScanner(
		ipscanner.WithLogger(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		ipscanner.WithWarpPrivateKey("yGXeX7gMyUIZmK5QIgC7+XX5USUSskQvBYiQ6LdkiXI="),
		ipscanner.WithWarpPeerPublicKey("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="),
		ipscanner.WithUseIPv4(*v4),
		ipscanner.WithUseIPv6(*v6),
		ipscanner.WithMaxDesirableRTT(*rtt),
		ipscanner.WithCidrList(warp.WarpPrefixes()),
		ipscanner.WithIPQueueSize(0xffff),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	scanner.Run(ctx)
	<-ctx.Done()

	ipList := scanner.GetAvailableIPs()

	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("Address", "RTT (ping)", "Time")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	for _, info := range ipList {
		tbl.AddRow(info.AddrPort, info.RTT, info.CreatedAt.Format(time.DateTime))
	}

	tbl.Print()
}
