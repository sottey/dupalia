package main

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

var csvHeader = []string{"hostname", "scan_root", "relative_path", "full_path", "filename", "extension", "size_bytes", "modified_time", "created_time", "mode", "uid", "gid", "inode", "device", "sha256", "hash_status"}

type Options struct {
	Roots            []string
	Output           string
	NoHash           bool
	CrossFilesystems bool
	Workers          int
	ProgressEvery    int
}

type Result struct {
	Hostname, Output                                                                             string
	Roots                                                                                        []string
	FilesWritten, FilesHashed, HashErrors, DirectoriesSkipped, MetadataErrors, BoundariesSkipped int64
	TotalBytes, BytesHashed                                                                      int64
	Elapsed                                                                                      time.Duration
}

type scanner struct {
	options          Options
	hostname, output string
	writer           *csv.Writer
	stderr           io.Writer
	mu               sync.Mutex // owns both CSV serialization and result mutation.
	result           Result
	discoveredFiles  int64
	discoveredBytes  int64
}

func Run(ctx context.Context, options Options, stderr io.Writer) (Result, error) {
	start := time.Now()
	if options.Workers < 1 {
		return Result{}, errors.New("--workers must be at least 1")
	}
	if options.ProgressEvery < 0 {
		return Result{}, errors.New("--progress-every must be zero or greater")
	}
	if len(options.Roots) == 0 {
		return Result{}, errors.New("at least one scan root is required")
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return Result{}, fmt.Errorf("determine hostname: %w", err)
	}
	roots, rootDevices, err := validateRoots(options.Roots)
	if err != nil {
		return Result{}, err
	}
	output, err := absoluteClean(options.Output)
	if err != nil {
		return Result{}, fmt.Errorf("resolve output path: %w", err)
	}
	for _, root := range roots {
		if containsPath(root, output) {
			return Result{}, fmt.Errorf("output CSV must not be inside a scan root: %s", output)
		}
	}
	file, err := os.Create(output)
	if err != nil {
		return Result{}, fmt.Errorf("create output CSV: %w", err)
	}
	defer file.Close()
	w := csv.NewWriter(file)
	if err := w.Write(csvHeader); err != nil {
		return Result{}, fmt.Errorf("write CSV header: %w", err)
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return Result{}, fmt.Errorf("flush CSV header: %w", err)
	}

	s := &scanner{options: options, hostname: hostname, output: output, writer: w, stderr: stderr, result: Result{Hostname: hostname, Output: output, Roots: roots}}
	jobs := make(chan fileJob, options.Workers*2)
	var workers sync.WaitGroup
	for range options.Workers {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				s.processFile(ctx, job)
			}
		}()
	}

	interrupted := false
	for i, root := range roots {
		if ctx.Err() != nil {
			interrupted = true
			break
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if walkErr != nil {
				s.warn("unable to access: %s: %v", path, walkErr)
				s.incrementDirectoryIf(entry)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if path == root {
				return nil
			}
			if path == output {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.Type()&fs.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				s.metadataError(path, err)
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !options.CrossFilesystems && deviceOf(info) != rootDevices[i] {
				if info.IsDir() {
					s.mu.Lock()
					s.result.BoundariesSkipped++
					s.mu.Unlock()
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				s.metadataError(path, err)
				return nil
			}
			s.discovered(path, info.Size())
			select {
			case jobs <- fileJob{root: root, path: path, relative: relative, info: info}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			close(jobs)
			workers.Wait()
			s.finish(file)
			return s.result, fmt.Errorf("scan root %s: %w", root, err)
		}
		if errors.Is(err, context.Canceled) {
			interrupted = true
			break
		}
	}
	close(jobs)
	workers.Wait()
	s.finish(file)
	s.result.Elapsed = time.Since(start)
	if interrupted {
		return s.result, context.Canceled
	}
	return s.result, nil
}

type fileJob struct {
	root, path, relative string
	info                 fs.FileInfo
}

func (s *scanner) processFile(ctx context.Context, job fileJob) {
	if ctx.Err() != nil {
		return
	}
	row := recordFor(s.hostname, job)
	if s.options.NoHash {
		row[14], row[15] = "", "skipped"
		s.writeRow(row, job.info.Size(), false, false)
		return
	}
	if ctx.Err() != nil {
		return
	}
	f, err := openNoFollow(job.path)
	if err != nil {
		s.warn("unable to hash: %s: %v", job.path, err)
		row[15] = "read_error"
		s.writeRow(row, job.info.Size(), false, true)
		return
	}
	h := sha256.New()
	_, copyErr := copyWithContext(ctx, h, f)
	closeErr := f.Close()
	if errors.Is(copyErr, context.Canceled) {
		s.warn("hash interrupted: %s", job.path)
		row[15] = "read_error"
		s.writeRow(row, job.info.Size(), false, true)
		return
	}
	post, statErr := os.Stat(job.path)
	if copyErr != nil || closeErr != nil || statErr != nil || post.Size() != job.info.Size() || !post.ModTime().Equal(job.info.ModTime()) {
		if copyErr != nil || closeErr != nil {
			s.warn("unable to hash: %s: %v", job.path, firstError(copyErr, closeErr))
		} else if statErr != nil {
			s.warn("unable to re-stat after hashing: %s: %v", job.path, statErr)
		} else {
			s.warn("file changed during scanning: %s", job.path)
		}
		row[15] = "read_error"
		s.writeRow(row, job.info.Size(), false, true)
		return
	}
	row[14], row[15] = fmt.Sprintf("%x", h.Sum(nil)), "ok"
	s.writeRow(row, job.info.Size(), true, false)
}

// copyWithContext hashes in fixed-size chunks, checking for cancellation
// between reads. Its memory use stays bounded regardless of file size.
func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 1024*1024)
	var written int64
	for {
		if err := ctx.Err(); err != nil {
			return written, err
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			m, writeErr := dst.Write(buffer[:n])
			written += int64(m)
			if writeErr != nil {
				return written, writeErr
			}
			if m != n {
				return written, io.ErrShortWrite
			}
		}
		if readErr == io.EOF {
			return written, nil
		}
		if readErr != nil {
			return written, readErr
		}
	}
}

func (s *scanner) writeRow(row []string, size int64, hashed, hashError bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.writer.Write(row); err != nil {
		s.warnLocked("write CSV row: %v", err)
		return
	}
	s.writer.Flush()
	s.result.FilesWritten++
	s.result.TotalBytes += size
	if hashed {
		s.result.FilesHashed++
		s.result.BytesHashed += size
	}
	if hashError {
		s.result.HashErrors++
	}
}
func (s *scanner) finish(file *os.File) {
	s.mu.Lock()
	s.writer.Flush()
	if err := s.writer.Error(); err != nil {
		s.warnLocked("flush CSV: %v", err)
	}
	if err := file.Sync(); err != nil {
		s.warnLocked("sync CSV: %v", err)
	}
	s.mu.Unlock()
}
func (s *scanner) warn(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.warnLocked(format, args...)
}
func (s *scanner) warnLocked(format string, args ...any) {
	fmt.Fprintf(s.stderr, "WARNING: "+format+"\n", args...)
}
func (s *scanner) metadataError(path string, err error) {
	s.warn("unable to stat: %s: %v", path, err)
	s.mu.Lock()
	s.result.MetadataErrors++
	s.mu.Unlock()
}
func (s *scanner) incrementDirectoryIf(entry fs.DirEntry) {
	if entry != nil && entry.IsDir() {
		s.mu.Lock()
		s.result.DirectoriesSkipped++
		s.mu.Unlock()
	}
}
func (s *scanner) discovered(path string, size int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discoveredFiles++
	s.discoveredBytes += size
	if s.options.ProgressEvery > 0 && s.discoveredFiles%int64(s.options.ProgressEvery) == 0 {
		fmt.Fprintf(s.stderr, "%d files | %s | hashed %s | current: %s\n", s.discoveredFiles, humanBytes(s.discoveredBytes), humanBytes(s.result.BytesHashed), path)
	}
}

func recordFor(hostname string, job fileJob) []string {
	info := job.info
	uid, gid, ino, dev := statFields(info)
	name := filepath.Base(job.path)
	ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(name)), ".")
	return []string{hostname, job.root, filepath.ToSlash(job.relative), job.path, name, ext, fmt.Sprint(info.Size()), info.ModTime().Format(time.RFC3339Nano), "", info.Mode().String(), fmt.Sprint(uid), fmt.Sprint(gid), fmt.Sprint(ino), fmt.Sprint(dev), "", ""}
}
func openNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
func absoluteClean(path string) (string, error) { return filepath.Abs(filepath.Clean(path)) }
func validateRoots(input []string) ([]string, []uint64, error) {
	roots := make([]string, len(input))
	devices := make([]uint64, len(input))
	for i, supplied := range input {
		root, err := absoluteClean(supplied)
		if err != nil {
			return nil, nil, err
		}
		info, err := os.Lstat(root)
		if err != nil {
			return nil, nil, fmt.Errorf("access scan root %s: %w", root, err)
		}
		if !info.IsDir() {
			return nil, nil, fmt.Errorf("scan root is not a directory: %s", root)
		}
		roots[i], devices[i] = root, deviceOf(info)
	}
	for i := range roots {
		for j := i + 1; j < len(roots); j++ {
			if containsPath(roots[i], roots[j]) || containsPath(roots[j], roots[i]) {
				return nil, nil, fmt.Errorf("overlapping scan roots: %s and %s", roots[i], roots[j])
			}
		}
	}
	return roots, devices, nil
}
func containsPath(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
func statFields(info fs.FileInfo) (uid, gid, ino, dev uint64) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	return uint64(stat.Uid), uint64(stat.Gid), uint64(stat.Ino), uint64(stat.Dev)
}
func deviceOf(info fs.FileInfo) uint64 { _, _, _, dev := statFields(info); return dev }
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
