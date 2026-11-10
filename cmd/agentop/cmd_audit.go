package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/rossoctl/cortex/cmd/agentop/tui"
)

// runAudit opens the audit pane on its own, over a records file rather than a cortex. It is the
// way to watch a proxy other than cortex that runs the same ocsf-audit sink: point the sink's
// file exporter at a file and this at the same file. Verification is the pane's own, as in
// `agentop observe`; nothing here trusts the writer.
func runAudit(args []string, stdout, stderr io.Writer) int {
	opts, code, ok := parseAuditFlags(args, stderr)
	if !ok {
		return code
	}
	opts.Version = displayVersion()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigs)
	go func() {
		select {
		case <-sigs:
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := tui.RunAuditFile(ctx, opts); err != nil {
		fmt.Fprintf(stderr, "agentop audit: %v\n", err)
		return 1
	}
	return 0
}

// parseAuditFlags reads `agentop audit`'s flags. ok is false when the command should exit with
// code instead of opening the viewer: --help (0) or a bad invocation (2).
func parseAuditFlags(args []string, stderr io.Writer) (opts tui.AuditFileOptions, code int, ok bool) {
	fs := flag.NewFlagSet("agentop audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "",
		"the NDJSON `path` the policy engine's ocsf-audit sink writes through its file exporter "+
			"(default ~/.cortex/audit/records.ndjson, where a local cortex's sink writes)")
	keys := fs.String("keys", "",
		"`directory` of the signing authority's public keys, one <key id>.pub.pem each "+
			"(default ~/.cortex/audit/keys)")
	ledger := fs.String("ledger", "",
		"gRPC address (host:port) of the ARE immutable ledger that receipts the records; "+
			"each record is then checked against the ledger's copy")
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), `agentop audit — verify and watch a policy engine's signed audit records

Usage:
  agentop audit [--file PATH] [--keys DIR] [--ledger HOST:PORT]

Follows the records file as the sink appends to it, and checks every record here:
its fingerprint and signature, its link to the record before it, missing stream
positions, and, with --ledger, the ledger's receipt. An edit to the file, a
deleted line or a replaced file is reread at once, so tampering shows as it
happens. No cortex is needed.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return opts, 0, false
		}
		return opts, 2, false
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "agentop audit: unexpected argument %q; the file is --file\n", fs.Arg(0))
		return opts, 2, false
	}
	opts.File, opts.KeysDir, opts.Ledger = *file, *keys, *ledger
	if opts.File == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "agentop audit: no home directory to find the records file in (%v); pass --file\n", err)
			return opts, 2, false
		}
		// The path cortex's session.audit follows and its sink's exporter names
		// (cmd/cortex/audit.go). Repeated rather than imported: it lives in cortex's main package.
		opts.File = filepath.Join(home, ".cortex", "audit", "records.ndjson")
	}
	return opts, 0, true
}
