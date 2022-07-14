package scanning

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// getTransport is setting timetout and proxy on tranport
func getTransport(timeout time.Duration) *http.Transport {
	// set timeout
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			DualStack: true,
		}).DialContext,
	}
	return transport
}
