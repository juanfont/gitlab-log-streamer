package streamer

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func appendToFile(t *testing.T, path, content string) {
	t.Helper()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

// collectLines runs one readLines pass and returns the lines it delivered.
func collectLines(t *testing.T, tailer *logTailer) []string {
	t.Helper()

	lines := []string{}
	err := tailer.readLines(func(line []byte) error {
		lines = append(lines, string(line))
		return nil
	})
	if err != nil {
		t.Fatalf("readLines() error = %v", err)
	}

	return lines
}

func expectLines(t *testing.T, got []string, want ...string) {
	t.Helper()

	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got lines %q, want %q", got, want)
	}
}

func TestLogTailerReadsOnlyAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_json.log")
	appendToFile(t, path, "one\ntwo\n")
	tailer := newLogTailer(path)

	expectLines(t, collectLines(t, tailer), "one", "two")

	appendToFile(t, path, "three\n")
	expectLines(t, collectLines(t, tailer), "three")

	// Nothing new: nothing delivered.
	expectLines(t, collectLines(t, tailer))
}

func TestLogTailerHoldsPartialLineUntilComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_json.log")
	appendToFile(t, path, "one\n{\"half\":")
	tailer := newLogTailer(path)

	expectLines(t, collectLines(t, tailer), "one")

	appendToFile(t, path, "\"line\"}\n")
	expectLines(t, collectLines(t, tailer), `{"half":"line"}`)
}

func TestLogTailerRestartsAfterTruncation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_json.log")
	appendToFile(t, path, "old-1\nold-2\nold-3\n")
	tailer := newLogTailer(path)
	expectLines(t, collectLines(t, tailer), "old-1", "old-2", "old-3")

	// logrotate copytruncate: same inode, size drops below our offset.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendToFile(t, path, "new-1\n")

	expectLines(t, collectLines(t, tailer), "new-1")
}

// With copytruncate the file can regrow past our offset before we look at it
// (the kernel coalesces the truncate and the following writes into one
// event), so "size < offset" alone misses the truncation.
func TestLogTailerDetectsTruncationAfterRegrowth(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_json.log")
	appendToFile(t, path, "old-1\nold-2\n")
	tailer := newLogTailer(path)
	expectLines(t, collectLines(t, tailer), "old-1", "old-2")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	// Same length as before, then more.
	appendToFile(t, path, "new-1\nnew-2\nnew-3\n")

	expectLines(t, collectLines(t, tailer), "new-1", "new-2", "new-3")
}

func TestLogTailerFollowsRenameRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth_json.log")
	appendToFile(t, path, "old-1\n")
	tailer := newLogTailer(path)
	expectLines(t, collectLines(t, tailer), "old-1")

	// Written just before rotation: must still be picked up from the old file.
	appendToFile(t, path, "old-2\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}

	// Rotated away, new file not created yet.
	expectLines(t, collectLines(t, tailer), "old-2")

	appendToFile(t, path, "new-1\nnew-2\n")
	expectLines(t, collectLines(t, tailer), "new-1", "new-2")
}

func TestLogTailerRetriesLineAfterCallbackError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth_json.log")
	appendToFile(t, path, "one\ntwo\nthree\n")
	tailer := newLogTailer(path)

	errDB := errors.New("db is locked")
	delivered := []string{}
	err := tailer.readLines(func(line []byte) error {
		if string(line) == "two" {
			return errDB
		}
		delivered = append(delivered, string(line))
		return nil
	})
	if !errors.Is(err, errDB) {
		t.Fatalf("readLines() error = %v, want %v", err, errDB)
	}
	expectLines(t, delivered, "one")

	// The failed line is retried, and nothing before it is re-delivered.
	expectLines(t, collectLines(t, tailer), "two", "three")
}

func TestLogTailerMissingFile(t *testing.T) {
	tailer := newLogTailer(filepath.Join(t.TempDir(), "missing.log"))

	err := tailer.readLines(func([]byte) error { return nil })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("readLines() error = %v, want os.ErrNotExist", err)
	}
}

// Lines longer than bufio.Scanner's default 64 KB limit must still be read.
func TestLogTailerHandlesVeryLongLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit_json.log")
	long := strings.Repeat("x", 512*1024)
	appendToFile(t, path, "before\n"+long+"\nafter\n")
	tailer := newLogTailer(path)

	lines := collectLines(t, tailer)
	if len(lines) != 3 || lines[0] != "before" || lines[1] != long || lines[2] != "after" {
		t.Fatalf("expected 3 lines including the 512 KB one, got %d lines", len(lines))
	}
}
