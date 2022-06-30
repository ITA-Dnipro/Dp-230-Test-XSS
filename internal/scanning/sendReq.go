package scanning

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"test/internal/model"

	"github.com/hahwul/dalfox/v2/pkg/verification"
)

// SendReq is sending http request (handled GET/POST)
func SendReq(req *http.Request, payload string, options model.Options) (string, *http.Response, bool, bool, error) {
	netTransport := getTransport(options)

	client := &http.Client{
		Timeout:   time.Duration(options.Timeout) * time.Second,
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
	if strings.Contains(body, payload) {
		return true
	}
	return false
}
