package scanning

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"

	"test/internal/model"
)

// getTransport is setting timetout and proxy on tranport
func getTransport(options model.Options) *http.Transport {
	// set timeout
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			Renegotiation:      tls.RenegotiateOnceAsClient,
		},
		DisableKeepAlives: true,
		DialContext: (&net.Dialer{
			Timeout:   time.Duration(options.Timeout) * time.Second,
			DualStack: true,
		}).DialContext,
	}
	// if use proxy mode , set proxy
	if options.ProxyAddress != "" {
		proxyAddress, err := url.Parse(options.ProxyAddress)
		_ = proxyAddress
		//validate proxy
		if err != nil {
		}
		transport.Proxy = http.ProxyURL(proxyAddress)
	}
	return transport
}
