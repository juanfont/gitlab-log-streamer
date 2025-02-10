package streamer

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	prometheusNamespace = "gitlab_log_streamer"
)

// audit_log_events received
var auditLogEventsReceived = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: prometheusNamespace,
	Name:      "audit_log_events_received",
	Help:      "Number of audit log events received",
})

// auth_log_events received
var authLogEventsReceived = promauto.NewCounter(prometheus.CounterOpts{
	Namespace: prometheusNamespace,
	Name:      "auth_log_events_received",
	Help:      "Number of auth log events received",
})
