package main

import (
	"bytes"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlanWritesOnlyUniqueMissingHashes(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.csv")
	destination := filepath.Join(directory, "destination.csv")
	output := filepath.Join(directory, "plan.csv")
	writeInventory(t, source, [][]string{
		inventoryRow("/source/present", "present", "10", "hash-present", "ok"),
		inventoryRow("/source/missing-first", "missing-first", "20", "hash-missing", "ok"),
		inventoryRow("/source/missing-second", "missing-second", "20", "hash-missing", "ok"),
		inventoryRow("/source/unreadable", "unreadable", "30", "", "read_error"),
	})
	writeInventory(t, destination, [][]string{
		inventoryRow("/destination/present", "present", "10", "hash-present", "ok"),
		inventoryRow("/destination/skipped", "skipped", "2", "", "skipped"),
	})
	var stdout, stderr bytes.Buffer
	if code := runPlan([]string{"--source", source, "--destination", destination, "--output", output}, &stdout, &stderr); code != 0 {
		t.Fatalf("runPlan exit=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "missing: 1 (20 B)") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	rows := readCSV(t, output)
	if len(rows) != 2 {
		t.Fatalf("plan rows = %d, want 2", len(rows))
	}
	if got, want := strings.Join(rows[1], "|"), "host|/scan|missing-first|/source/missing-first|20|hash-missing|2"; got != want {
		t.Fatalf("plan row = %q, want %q", got, want)
	}
}

func TestPlanRejectsInvalidInventoryAndInputOverwrite(t *testing.T) {
	directory := t.TempDir()
	invalid := filepath.Join(directory, "invalid.csv")
	if err := os.WriteFile(invalid, []byte("not,a,dupalia,inventory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := runPlan([]string{"--source", invalid, "--destination", invalid, "--output", filepath.Join(directory, "plan.csv")}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "read header") {
		t.Fatalf("invalid inventory: exit=%d stderr=%q", code, stderr.String())
	}
	if code := runPlan([]string{"--source", invalid, "--destination", filepath.Join(directory, "destination.csv"), "--output", invalid}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "must not overwrite") {
		t.Fatalf("input overwrite: exit=%d stderr=%q", code, stderr.String())
	}
}

func writeInventory(t *testing.T, path string, rows [][]string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write(csvHeader); err != nil {
		t.Fatal(err)
	}
	writer.WriteAll(rows)
	if err := writer.Error(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func inventoryRow(fullPath, relativePath, size, hash, status string) []string {
	return []string{"host", "/scan", relativePath, fullPath, "file", "", size, "", "", "-rw-r--r--", "0", "0", "1", "1", hash, status}
}
