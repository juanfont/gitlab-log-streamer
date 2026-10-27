package streamer

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/rs/zerolog/log"
)

// logTailer reads a log file incrementally, delivering only the complete
// lines appended since the previous read.
//
// offset is the position just after the last line handed to the callback.
// A trailing partial line is never delivered and the offset is not moved
// past it, so it is read again (and delivered once complete) on the next
// call. The same applies to a line whose callback returned an error.
//
// Rotation is handled for both logrotate methods:
//   - copytruncate (GitLab Omnibus default): same file, truncated in place.
//     Detected when the size drops below offset, or when the bytes just
//     before offset are no longer the ones we read (the file was truncated
//     and regrew past offset before we looked). Either way: restart from 0
//     and let deduplication skip what was already stored.
//   - rename + create: the old file is drained through the open descriptor,
//     then the new file at path is read from 0.
type logTailer struct {
	path   string
	file   *os.File
	offset int64

	// anchor holds the last bytes consumed, ending at offset.
	anchor []byte
}

// anchorSize is how many bytes before offset are compared to detect a file
// that was rewritten underneath us. Log lines carry timestamps and
// correlation IDs, so a coincidental match is not a practical concern.
const anchorSize = 256

func newLogTailer(path string) *logTailer {
	return &logTailer{path: path}
}

// readLines calls fn for every complete line (without the trailing newline)
// appended since the previous call. If fn returns an error, reading stops
// and that line is delivered again on the next call.
func (t *logTailer) readLines(fn func(line []byte) error) error {
	if t.file == nil {
		if err := t.open(); err != nil {
			return err
		}
	}

	fi, err := t.file.Stat()
	if err != nil {
		return err
	}

	if t.truncated(fi.Size()) {
		log.Info().Str("path", t.path).Int64("offset", t.offset).Int64("size", fi.Size()).
			Msg("Log file truncated, reading from the start")
		t.reset()
	}

	if err := t.drain(fn); err != nil {
		return err
	}

	// Has the path been rotated to a new file? The old one is fully drained
	// at this point.
	pathFi, err := os.Stat(t.path)
	if errors.Is(err, os.ErrNotExist) {
		// Rotated away and not recreated yet; pick it up on a later call.
		return nil
	}
	if err != nil {
		return err
	}

	if os.SameFile(fi, pathFi) {
		return nil
	}

	log.Info().Str("path", t.path).Msg("Log file rotated, reading the new file from the start")
	t.file.Close()
	if err := t.open(); err != nil {
		return err
	}

	return t.drain(fn)
}

func (t *logTailer) open() error {
	f, err := os.Open(t.path)
	if err != nil {
		t.file = nil
		return err
	}

	t.file = f
	t.reset()

	return nil
}

func (t *logTailer) reset() {
	t.offset = 0
	t.anchor = t.anchor[:0]
}

// truncated reports whether the open file no longer holds the data we
// already read up to offset.
func (t *logTailer) truncated(size int64) bool {
	if size < t.offset {
		return true
	}
	if len(t.anchor) == 0 {
		return false
	}

	buf := make([]byte, len(t.anchor))
	if _, err := t.file.ReadAt(buf, t.offset-int64(len(t.anchor))); err != nil {
		return true
	}

	return !bytes.Equal(buf, t.anchor)
}

// advance moves offset past a consumed line and updates the anchor.
func (t *logTailer) advance(line []byte) {
	t.offset += int64(len(line))

	t.anchor = append(t.anchor, line...)
	if len(t.anchor) > anchorSize {
		t.anchor = append(t.anchor[:0], t.anchor[len(t.anchor)-anchorSize:]...)
	}
}

func (t *logTailer) drain(fn func(line []byte) error) error {
	if _, err := t.file.Seek(t.offset, io.SeekStart); err != nil {
		return err
	}

	r := bufio.NewReaderSize(t.file, 64*1024)
	for {
		line, err := r.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			// Any bytes read here are an incomplete line: leave them for
			// the next call.
			return nil
		}
		if err != nil {
			return err
		}

		if err := fn(bytes.TrimSuffix(line, []byte("\n"))); err != nil {
			return err
		}

		t.advance(line)
	}
}
