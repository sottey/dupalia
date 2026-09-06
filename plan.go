package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
)

var planHeader = []string{"source_hostname", "source_scan_root", "source_relative_path", "source_full_path", "size_bytes", "sha256", "source_hash_copies"}

type inventoryFile struct {
	hostname, scanRoot, relativePath, fullPath, hash string
	size                                             int64
	hashCopies                                       int
}

type inventorySummary struct {
	valid, skipped, readErrors, duplicateHashes int
	bytes                                       int64
}

// runPlan writes one row for every unique, successfully hashed source file that
// is not present by SHA-256 in the destination inventory. It never accesses the
// source or destination storage; it only reads inventories and writes the plan.
func runPlan(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("plan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var sourcePath, destinationPath, outputPath string
	flags.StringVar(&sourcePath, "source", "", "source inventory CSV")
	flags.StringVar(&destinationPath, "destination", "", "destination inventory CSV")
	flags.StringVar(&outputPath, "output", "", "copy-plan CSV to write")
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: dupalia plan --source SOURCE.csv --destination DESTINATION.csv --output PLAN.csv")
		fmt.Fprintln(stderr, "\nCreates a SHA-256 content manifest for files present in SOURCE but absent from DESTINATION. This command never copies, deletes, or changes storage files.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || sourcePath == "" || destinationPath == "" || outputPath == "" {
		flags.Usage()
		return 2
	}
	for _, path := range []string{sourcePath, destinationPath} {
		if samePath(path, outputPath) {
			fmt.Fprintln(stderr, "ERROR: --output must not overwrite an input inventory")
			return 2
		}
	}

	source, sourceSummary, err := readInventory(sourcePath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: read source inventory: %v\n", err)
		return 1
	}
	destination, destinationSummary, err := readInventory(destinationPath)
	if err != nil {
		fmt.Fprintf(stderr, "ERROR: read destination inventory: %v\n", err)
		return 1
	}

	missing := make([]inventoryFile, 0)
	for hash, sourceFile := range source {
		if _, present := destination[hash]; !present {
			missing = append(missing, sourceFile)
		}
	}
	sort.Slice(missing, func(i, j int) bool {
		if missing[i].size != missing[j].size {
			return missing[i].size > missing[j].size
		}
		return missing[i].fullPath < missing[j].fullPath
	})
	if err := writePlan(outputPath, missing); err != nil {
		fmt.Fprintf(stderr, "ERROR: write plan: %v\n", err)
		return 1
	}
	var missingBytes int64
	for _, file := range missing {
		missingBytes += file.size
	}
	fmt.Fprintf(stdout, "Plan complete. Unique source hashes: %d; destination hashes: %d; missing: %d (%s).\n", len(source), len(destination), len(missing), humanBytes(missingBytes))
	fmt.Fprintf(stdout, "Source excluded: %d skipped, %d read errors. Destination excluded: %d skipped, %d read errors.\n", sourceSummary.skipped, sourceSummary.readErrors, destinationSummary.skipped, destinationSummary.readErrors)
	fmt.Fprintf(stdout, "Copy plan: %s\n", outputPath)
	return 0
}

func readInventory(path string) (map[string]inventoryFile, inventorySummary, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, inventorySummary{}, err
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = len(csvHeader)
	header, err := reader.Read()
	if err != nil {
		return nil, inventorySummary{}, fmt.Errorf("read header: %w", err)
	}
	if !reflect.DeepEqual(header, csvHeader) {
		return nil, inventorySummary{}, errors.New("unexpected CSV header; expected a dupalia inventory")
	}
	files := make(map[string]inventoryFile)
	var summary inventorySummary
	for rowNumber := 2; ; rowNumber++ {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, inventorySummary{}, fmt.Errorf("row %d: %w", rowNumber, err)
		}
		switch row[15] {
		case "skipped":
			summary.skipped++
			continue
		case "read_error":
			summary.readErrors++
			continue
		case "ok":
			if row[14] == "" {
				return nil, inventorySummary{}, fmt.Errorf("row %d: hash_status is ok but sha256 is blank", rowNumber)
			}
		default:
			return nil, inventorySummary{}, fmt.Errorf("row %d: unknown hash_status %q", rowNumber, row[15])
		}
		size, err := strconv.ParseInt(row[6], 10, 64)
		if err != nil || size < 0 {
			return nil, inventorySummary{}, fmt.Errorf("row %d: invalid size_bytes %q", rowNumber, row[6])
		}
		file := inventoryFile{hostname: row[0], scanRoot: row[1], relativePath: row[2], fullPath: row[3], hash: row[14], size: size, hashCopies: 1}
		if existing, exists := files[file.hash]; exists {
			if existing.size != file.size {
				return nil, inventorySummary{}, fmt.Errorf("row %d: sha256 %s has conflicting sizes", rowNumber, file.hash)
			}
			summary.duplicateHashes++
			existing.hashCopies++
			files[file.hash] = existing
			continue
		}
		files[file.hash] = file
		summary.valid++
		summary.bytes += size
	}
	return files, summary, nil
}

func writePlan(path string, files []inventoryFile) error {
	output, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".dupalia-plan-*.csv")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	writer := csv.NewWriter(temporary)
	if err := writer.Write(planHeader); err != nil {
		temporary.Close()
		return err
	}
	for _, file := range files {
		if err := writer.Write([]string{file.hostname, file.scanRoot, file.relativePath, file.fullPath, strconv.FormatInt(file.size, 10), file.hash, strconv.Itoa(file.hashCopies)}); err != nil {
			temporary.Close()
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, output)
}

func samePath(first, second string) bool {
	firstAbs, firstErr := filepath.Abs(first)
	secondAbs, secondErr := filepath.Abs(second)
	return firstErr == nil && secondErr == nil && firstAbs == secondAbs
}
