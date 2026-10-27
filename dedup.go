package streamer

import (
	"hash/fnv"
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

// dedupKey identifies an event. The timestamp is part of the key because
// GitLab reuses correlation IDs for sequential events, and the line hash
// because one request can log several distinct events with the same
// correlation ID and millisecond timestamp. The key alone is enough for
// eviction, so the set stores nothing else: no event data is kept in memory.
type dedupKey struct {
	correlationID string
	unixNano      int64
	lineHash      uint64
}

// legacyLineHash is the hash of rows stored before line hashes existed
// (0.9.2 and older). lineHash never returns it for a real line.
const legacyLineHash = 0

// dedupSet remembers which events have already been stored and forwarded.
type dedupSet struct {
	m *xsync.MapOf[dedupKey, struct{}]
}

func newDedupSet() *dedupSet {
	return &dedupSet{m: xsync.NewMapOf[dedupKey, struct{}]()}
}

// seen reports whether the event was already stored. A legacy row (stored
// without a line hash) matches the first event with its correlation ID and
// time, which is the one older versions stored: they read the file in order
// and dropped the rest as duplicates. That match is then recorded under the
// event's real hash, so later events with the same correlation ID and time
// are new.
func (d *dedupSet) seen(correlationID string, t time.Time, hash uint64) bool {
	key := dedupKey{correlationID, t.UnixNano(), hash}
	if _, ok := d.m.Load(key); ok {
		return true
	}

	legacy := dedupKey{correlationID, t.UnixNano(), legacyLineHash}
	if _, ok := d.m.LoadAndDelete(legacy); ok {
		d.m.Store(key, struct{}{})
		return true
	}

	return false
}

func (d *dedupSet) add(correlationID string, t time.Time, hash uint64) {
	d.m.Store(dedupKey{correlationID, t.UnixNano(), hash}, struct{}{})
}

// evictBefore drops entries for events older than cutoff.
func (d *dedupSet) evictBefore(cutoff time.Time) {
	c := cutoff.UnixNano()
	d.m.Range(func(k dedupKey, _ struct{}) bool {
		if k.unixNano < c {
			d.m.Delete(k)
		}
		return true
	})
}

func (d *dedupSet) size() int {
	return d.m.Size()
}

// lineHash returns the dedup hash of a raw log line. It must be stable across
// processes, since it is stored in the DB and preloaded at startup.
func lineHash(line []byte) uint64 {
	h := fnv.New64a()
	h.Write(line)
	if sum := h.Sum64(); sum != legacyLineHash {
		return sum
	}

	return legacyLineHash + 1
}
