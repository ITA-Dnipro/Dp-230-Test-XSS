package scanning

import (
	"test/internal/model"
	"test/internal/optimization"
	"time"
)

// StaticAnalysis is found information on original req/res
func StaticAnalysis(target string, options model.Options, rl *rateLimiter) map[string]string {
	policy := make(map[string]string)
	req := optimization.GenerateNewRequest(target, "", options)
	_, resp, _, _, err := SendReq(req, "", time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return policy
	}
	if resp.Header["Content-Type"] != nil {
		policy["Content-Type"] = resp.Header["Content-Type"][0]
	}
	if resp.Header["Content-Security-Policy"] != nil {
		policy["Content-Security-Policy"] = resp.Header["Content-Security-Policy"][0]
		result := checkCSP(policy["Content-Security-Policy"])
		if result != "" {
			policy["BypassCSP"] = result
		}
	}
	if resp.Header["X-Frame-Options"] != nil {
		policy["X-Frame-Options"] = resp.Header["X-Frame-Options"][0]
	}
	if resp.Header["Strict-Transport-Security"] != nil {
		policy["Strict-Transport-Security"] = resp.Header["Strict-Transport-Security"][0]
	}
	if resp.Header["Access-Control-Allow-Origin"] != nil {
		policy["Access-Control-Allow-Origin"] = resp.Header["Access-Control-Allow-Origin"][0]
	}
	return policy
}
