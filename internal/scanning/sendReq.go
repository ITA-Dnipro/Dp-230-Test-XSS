package scanning

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/verification"
)

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, timeout time.Duration) (string, *http.Response, bool, bool, error) {
	netTransport := getTransport(10 * time.Second)

	client := &http.Client{
		Timeout:   timeout,
		Transport: netTransport,
	}

	resp, err := client.Do(req)
	if err != nil {
		//fmt.Printf("HTTP call failed: %v --> %v", req.URL.String(), err)
		return "", resp, false, false, err
	}
	defer resp.Body.Close()

	var reader io.ReadCloser
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			reader = resp.Body
		}
		defer reader.Close()
	default:
		reader = resp.Body
	}

	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return "", resp, false, false, err
	}

	str := string(bytes)

	if resp.Header["Content-Type"] != nil {
		if isAllowType(resp.Header["Content-Type"][0]) {
			vds := verification.VerifyDOM(str)
			vrs := verification.VerifyReflection(str, payload)
			return str, resp, vds, vrs, nil
		}
	}

	return str, resp, false, false, nil
}

// VerifyReflection is check reflected param for xss and mining
func VerifyReflection(body, payload string) bool {
	return strings.Contains(body, payload)
}
