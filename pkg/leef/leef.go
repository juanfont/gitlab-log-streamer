package leef

import "fmt"

type LEEFMessage struct {
	SyslogHeader    SyslogRFC5424Header
	LEEFVersion     string
	Vendor          string
	Product         string
	Version         string
	EventID         string
	Separator       string
	EventAttributes map[string]string
}

type SyslogRFC5424Header struct {
	Priority  int
	Timestamp string
	Hostname  string
}

func (h SyslogRFC5424Header) String() string {
	return fmt.Sprintf("<%d>1 %s %s", h.Priority, h.Timestamp, h.Hostname)
}

//1.0|41|^|src=192.0.2.0^dst=172.50.123.1^sev=5^cat=anomaly^srcPort=81^dstPort=21^usrName=joe.black

func (m LEEFMessage) String() string {
	// get a string of all EventAttributes in the form key=value joined with ^ as separator
	var eventAttributes string
	for k, v := range m.EventAttributes {
		eventAttributes += fmt.Sprintf("%s=%s^", k, v)
	}
	eventAttributes = eventAttributes[:len(eventAttributes)-1]

	return fmt.Sprintf("%s LEEF:%s|%s|%s|%s|%s|%s|%s",
		m.SyslogHeader,
		m.LEEFVersion,
		m.Vendor,
		m.Product,
		m.Version,
		m.EventID,
		m.Separator,
		eventAttributes,
	)
}
