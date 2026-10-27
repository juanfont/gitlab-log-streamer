package streamer

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestDedupSetSeenAfterAdd(t *testing.T) {
	d := newDedupSet()
	ts := time.Now()

	if d.seen("abc", ts) {
		t.Fatal("empty set must not report an event as seen")
	}

	d.add("abc", ts)

	if !d.seen("abc", ts) {
		t.Fatal("event must be seen after add")
	}
}

func TestDedupSetKeyIncludesTimestamp(t *testing.T) {
	d := newDedupSet()
	ts := time.Now()
	d.add("abc", ts)

	// GitLab reuses correlation IDs for sequential events.
	if d.seen("abc", ts.Add(time.Nanosecond)) {
		t.Fatal("same correlation ID at a different time must not be seen")
	}
}

func TestDedupSetEvictBefore(t *testing.T) {
	d := newDedupSet()
	now := time.Now()
	d.add("old", now.Add(-72*time.Hour))
	d.add("recent", now.Add(-time.Hour))

	d.evictBefore(now.Add(-48 * time.Hour))

	if d.seen("old", now.Add(-72*time.Hour)) {
		t.Error("entry older than the cutoff should have been evicted")
	}
	if !d.seen("recent", now.Add(-time.Hour)) {
		t.Error("entry newer than the cutoff should have been kept")
	}
	if d.size() != 1 {
		t.Errorf("expected 1 entry after eviction, got %d", d.size())
	}
}

// TestDedupSetMemoryShape pushes 500k synthetic events through the dedup set
// and checks the retained heap stays small. 0.9.1 kept full event structs
// here, which grew to several GB on busy instances.
func TestDedupSetMemoryShape(t *testing.T) {
	if testing.Short() {
		t.Skip("memory shape test skipped in -short mode")
	}

	const events = 500_000
	// Generous bound: real usage is ~100 B/entry. This fails if full events
	// (or anything of similar size) creep back into the set.
	const maxBytes = 150 << 20

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	d := newDedupSet()
	base := time.Now()
	for i := range events {
		// GitLab correlation IDs are 26-char ULIDs.
		d.add(fmt.Sprintf("01JB%022d", i), base.Add(time.Duration(i)*time.Millisecond))
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	retained := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("dedup set: %d entries, %.1f MB retained, %d B/entry",
		d.size(), float64(retained)/(1<<20), retained/events)

	if d.size() != events {
		t.Fatalf("expected %d entries, got %d", events, d.size())
	}
	if retained > maxBytes {
		t.Fatalf("dedup set retains %d MB for %d events, want < %d MB",
			retained>>20, events, maxBytes>>20)
	}
	runtime.KeepAlive(d)
}
