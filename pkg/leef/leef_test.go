package leef

import (
	"strings"
	"testing"
)

func TestSyslogRFC5424HeaderString(t *testing.T) {
	h := SyslogRFC5424Header{
		Priority:  110,
		Timestamp: "2024-04-16T10:00:00Z",
		Hostname:  "gitlab.example.com",
	}

	got := h.String()
	want := "<110>1 2024-04-16T10:00:00Z gitlab.example.com"
	if got != want {
		t.Errorf("header String() = %q, want %q", got, want)
	}
}

func TestLEEFMessageString(t *testing.T) {
	msg := LEEFMessage{
		SyslogHeader: SyslogRFC5424Header{
			Priority:  110,
			Timestamp: "2024-04-16T10:00:00Z",
			Hostname:  "gitlab.example.com",
		},
		LEEFVersion: "2.0",
		Vendor:      "GitLab Inc.",
		Product:     "GitLab",
		Version:     "16.9.1",
		EventID:     "User logged in",
		Separator:   "^",
		EventAttributes: map[string]string{
			"usrName": "juan",
			"src":     "192.0.2.1",
			"sev":     "INFO",
		},
	}

	got := msg.String()

	wantPrefix := "<110>1 2024-04-16T10:00:00Z gitlab.example.com " +
		"LEEF:2.0|GitLab Inc.|GitLab|16.9.1|User logged in|^|"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("LEEF message %q does not start with %q", got, wantPrefix)
	}

	// Attribute order is not deterministic (map iteration), so parse the
	// key=value pairs instead of comparing the full string.
	attrPart := strings.TrimPrefix(got, wantPrefix)
	attrs := map[string]string{}
	for _, pair := range strings.Split(attrPart, "^") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			t.Fatalf("malformed attribute %q in %q", pair, attrPart)
		}
		attrs[k] = v
	}

	want := msg.EventAttributes
	if len(attrs) != len(want) {
		t.Fatalf("got %d attributes, want %d: %v", len(attrs), len(want), attrs)
	}
	for k, v := range want {
		if attrs[k] != v {
			t.Errorf("attribute %s = %q, want %q", k, attrs[k], v)
		}
	}
}
