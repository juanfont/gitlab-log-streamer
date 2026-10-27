package streamer

import (
	"time"

	"github.com/puzpuzpuz/xsync/v3"
)

// dedupKey identifies an event. The timestamp is part of the key because
// GitLab reuses correlation IDs for sequential events. The key alone is
// enough for eviction, so the set stores nothing else: no event data is
// kept in memory.
type dedupKey struct {
	correlationID string
	unixNano      int64
}

// dedupSet remembers which events have already been stored and forwarded.
type dedupSet struct {
	m *xsync.MapOf[dedupKey, struct{}]
}

func newDedupSet() *dedupSet {
	return &dedupSet{m: xsync.NewMapOf[dedupKey, struct{}]()}
}

func (d *dedupSet) seen(correlationID string, t time.Time) bool {
	_, ok := d.m.Load(dedupKey{correlationID, t.UnixNano()})
	return ok
}

func (d *dedupSet) add(correlationID string, t time.Time) {
	d.m.Store(dedupKey{correlationID, t.UnixNano()}, struct{}{})
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
