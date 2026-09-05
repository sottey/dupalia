package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	var output string
	var noHash bool
	var crossFilesystems bool
	var workers, progressEvery int

	flag.StringVar(&output, "output", "", "CSV output path (default: dupalia-<hostname>.csv)")
	flag.BoolVar(&noHash, "no-hash", false, "record metadata without reading file contents")
	flag.BoolVar(&crossFilesystems, "cross-filesystems", false, "allow traversal into nested mounted filesystems")
	flag.IntVar(&workers, "workers", 1, "number of bounded hashing workers (minimum 1)")
	flag.IntVar(&progressEvery, "progress-every", 10000, "print progress every N files; 0 disables it")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: dupalia [flags] DIRECTORY [DIRECTORY ...]\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if output == "" {
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			fmt.Fprintln(os.Stderr, "ERROR: unable to determine hostname")
			os.Exit(1)
		}
		output = defaultOutputPath(hostname)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result, err := Run(ctx, Options{
		Roots:            flag.Args(),
		Output:           output,
		NoHash:           noHash,
		CrossFilesystems: crossFilesystems,
		Workers:          workers,
		ProgressEvery:    progressEvery,
	}, os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		if ctx.Err() != nil {
			printSummary(result, true, os.Stderr)
		}
		os.Exit(1)
	}
	printSummary(result, false, os.Stderr)
}

func printSummary(result Result, interrupted bool, stderr *os.File) {
	if interrupted {
		fmt.Fprintln(stderr, "Scan interrupted; the partial CSV is valid through its last written row.")
	} else {
		fmt.Fprintln(stderr, "Scan complete.")
	}
	fmt.Fprintf(stderr, "hostname: %s\nscan roots: %v\nfiles written: %d (%s)\nfiles hashed: %d (%s)\nhash read errors: %d\ndirectories skipped: %d\nfiles skipped (metadata): %d\nfilesystem boundaries skipped: %d\nelapsed: %s\nCSV output: %s\n",
		result.Hostname, result.Roots, result.FilesWritten, humanBytes(result.TotalBytes), result.FilesHashed, humanBytes(result.BytesHashed), result.HashErrors, result.DirectoriesSkipped, result.MetadataErrors, result.BoundariesSkipped, result.Elapsed.Round(1e6), result.Output)
}

func defaultOutputPath(hostname string) string {
	return filepath.Clean("dupalia-" + hostname + ".csv")
}
