package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestRunWritesExpectedInventory(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "Photos", "hello, \"world\".JPG"), "hello")
	writeTestFile(t, filepath.Join(root, "sp ace", "plain"), "x")
	writeTestFile(t, filepath.Join(root, "unicode-ø", "café.TAR.GZ"), "contents")
	if err := os.Symlink(filepath.Join(root, "Photos"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.csv")
	result, err := Run(context.Background(), Options{Roots: []string{root}, Output: output, Workers: 1}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesWritten != 3 || result.FilesHashed != 3 {
		t.Fatalf("result = %+v", result)
	}
	rows := readCSV(t, output)
	if !reflect.DeepEqual(rows[0], csvHeader) {
		t.Fatalf("header = %q", rows[0])
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d", len(rows))
	}
	byName := make(map[string][]string)
	for _, row := range rows[1:] {
		byName[row[4]] = row
	}
	quoted := byName["hello, \"world\".JPG"]
	if quoted[2] != "Photos/hello, \"world\".JPG" || quoted[5] != "jpg" {
		t.Fatalf("quoted row = %q", quoted)
	}
	if got, want := quoted[14], sha256Text("hello"); got != want {
		t.Fatalf("sha = %q, want %q", got, want)
	}
	if byName["plain"][5] != "" || byName["café.TAR.GZ"][5] != "gz" {
		t.Fatalf("extensions = %q, %q", byName["plain"][5], byName["café.TAR.GZ"][5])
	}
	if strings.Contains(strings.Join(rows[1][3:], ","), "linked") {
		t.Fatal("symlink was included")
	}
}

func TestNoHashAndOutputExclusion(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "one.txt"), "one")
	output := filepath.Join(root, "inventory.csv")
	if _, err := Run(context.Background(), Options{Roots: []string{root}, Output: output, NoHash: true, Workers: 1}, os.Stderr); err == nil || !strings.Contains(err.Error(), "must not be inside") {
		t.Fatalf("output inside root was accepted: %v", err)
	}
	output = filepath.Join(t.TempDir(), "inventory.csv")
	result, err := Run(context.Background(), Options{Roots: []string{root}, Output: output, NoHash: true, Workers: 1}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesWritten != 1 {
		t.Fatalf("result = %+v", result)
	}
	row := readCSV(t, output)[1]
	if row[14] != "" || row[15] != "skipped" {
		t.Fatalf("no-hash row = %q", row)
	}
}

func TestRootValidation(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, roots := range [][]string{{root, root}, {root, filepath.Join(root, ".")}, {root, child}} {
		_, err := Run(context.Background(), Options{Roots: roots, Output: filepath.Join(t.TempDir(), "out.csv"), Workers: 1}, os.Stderr)
		if err == nil || !strings.Contains(err.Error(), "overlapping") {
			t.Fatalf("roots %q: %v", roots, err)
		}
	}
	if _, err := Run(context.Background(), Options{Roots: []string{root}, Output: filepath.Join(t.TempDir(), "out.csv"), Workers: 0}, os.Stderr); err == nil {
		t.Fatal("workers=0 accepted")
	}
}

func TestMultipleRootsAndSpecialFiles(t *testing.T) {
	parent := t.TempDir()
	first, second := filepath.Join(parent, "first"), filepath.Join(parent, "second")
	writeTestFile(t, filepath.Join(first, "a"), "a")
	writeTestFile(t, filepath.Join(second, "b"), "b")
	pipe := filepath.Join(first, "ignored-pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "out.csv")
	result, err := Run(context.Background(), Options{Roots: []string{first, second}, Output: output, Workers: 2}, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	if result.FilesWritten != 2 {
		t.Fatalf("result = %+v", result)
	}
	for _, row := range readCSV(t, output)[1:] {
		if row[4] == "ignored-pipe" {
			t.Fatal("special file was included")
		}
	}
}

func TestCopyWithContextStopsBetweenChunks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader := strings.NewReader(strings.Repeat("x", 2*1024*1024))
	writer := cancelAfterFirstWrite{cancel: cancel}
	written, err := copyWithContext(ctx, &writer, reader)
	if err != context.Canceled {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if written != 1024*1024 || writer.writes != 1 {
		t.Fatalf("written=%d writes=%d", written, writer.writes)
	}
}

type cancelAfterFirstWrite struct {
	cancel context.CancelFunc
	writes int
}

func (w *cancelAfterFirstWrite) Write(data []byte) (int, error) {
	w.writes++
	w.cancel()
	return len(data), nil
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}
func sha256Text(text string) string {
	sum := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", sum)
}
