package streamer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitForRows polls until the auth table has want rows or the deadline passes.
func waitForRows(t *testing.T, s *GitLabLogStreamer, want int64) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		count := countRows(t, s, &AuthEvent{})
		if count == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %d auth events, have %d", want, count)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestWatchLoopFollowsRotation(t *testing.T) {
	now := time.Now()
	s := newTestStreamer(t, "", authLine("before", now, "m")+"\n")
	if err := s.readAuthLogFile(); err != nil {
		t.Fatal(err)
	}

	watcher, err := s.newLogWatcher()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.runWatchLoop(watcher, nil)
		close(done)
	}()
	t.Cleanup(func() {
		watcher.Close()
		<-done
	})

	// An append is picked up via a Write event.
	appendToFile(t, s.cfg.AuthLogPath, authLine("appended", now, "m")+"\n")
	waitForRows(t, s, 2)

	// Rename rotation: the new file is picked up via the directory watch.
	if err := os.Rename(s.cfg.AuthLogPath, s.cfg.AuthLogPath+".1"); err != nil {
		t.Fatal(err)
	}
	appendToFile(t, s.cfg.AuthLogPath, authLine("after-rotation", now, "m")+"\n")
	waitForRows(t, s, 3)

	// copytruncate rotation: the same file is truncated and rewritten.
	if err := os.Truncate(s.cfg.AuthLogPath, 0); err != nil {
		t.Fatal(err)
	}
	appendToFile(t, s.cfg.AuthLogPath, authLine("after-truncate", now, "m")+"\n")
	waitForRows(t, s, 4)
}

func TestWatchLoopPollsWithoutEvents(t *testing.T) {
	s := newTestStreamer(t, "", "")

	watcher, err := s.newLogWatcher()
	if err != nil {
		t.Fatal(err)
	}
	// Stop fsnotify from delivering anything so only the poll can find the line.
	watcher.Remove(filepath.Dir(s.cfg.AuthLogPath))

	poll := make(chan time.Time)
	done := make(chan struct{})
	go func() {
		s.runWatchLoop(watcher, poll)
		close(done)
	}()
	t.Cleanup(func() {
		watcher.Close()
		<-done
	})

	appendToFile(t, s.cfg.AuthLogPath, authLine("polled", time.Now(), "m")+"\n")
	poll <- time.Now()
	waitForRows(t, s, 1)
}

func TestWatchLoopIgnoresOtherFilesInDirectory(t *testing.T) {
	s := newTestStreamer(t, "", "")
	readsBefore := s.authTailer.offset

	other := filepath.Join(filepath.Dir(s.cfg.AuthLogPath), "production_json.log")
	appendToFile(t, other, authLine("not-ours", time.Now(), "m")+"\n")

	watcher, err := s.newLogWatcher()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		s.runWatchLoop(watcher, nil)
		close(done)
	}()
	appendToFile(t, other, authLine("still-not-ours", time.Now(), "m")+"\n")
	time.Sleep(100 * time.Millisecond)
	watcher.Close()
	<-done

	if count := countRows(t, s, &AuthEvent{}); count != 0 {
		t.Fatalf("events from other files must be ignored, got %d", count)
	}
	if s.authTailer.offset != readsBefore {
		t.Fatalf("auth tailer must not have moved, offset %d", s.authTailer.offset)
	}
}
