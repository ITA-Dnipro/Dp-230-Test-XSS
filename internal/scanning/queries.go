package scanning

import (
	"context"
	"net/http"
	"strings"
	"test/internal/model"
	"test/internal/optimization"
	"test/internal/verification"
	"time"
)

// Queries is struct of queries
type Queries struct {
	request  *http.Request
	metadata map[string]string
}

func (q *Queries) check(ctx context.Context) *model.PoC {
	//rl.Block(k.Host)
	if !checkPType(q.metadata["type"]) {
		return nil
	}
	resbody, _, vds, vrs, err := SendReq(q.request, q.metadata["payload"], 10*time.Second)
	if err != nil {
		return nil
	}
	abs := optimization.Abstraction(resbody, q.metadata["payload"])
	if vrs {
		if !containsFromArray(abs, q.metadata["type"]) && !strings.Contains(q.metadata["type"], "inHTML") {
			vrs = false
		}
	}
	if !checkPType(q.metadata["type"]) {
		return nil
	}
	if strings.Contains(q.metadata["type"], "inJS") {
		if !vrs {
			return nil
		}
		if verification.VerifyReflection(resbody, "\\"+q.metadata["payload"]) {
			if !strings.Contains(q.metadata["payload"], "\\") {
				return nil
			}
		}
		code := CodeView(resbody, q.metadata["payload"])
		poc := &model.PoC{
			Type:       "R",
			InjectType: q.metadata["type"],
			Method:     q.request.Method,
			Data:       q.request.URL.String(),
			Param:      q.metadata["param"],
			Payload:    q.metadata["payload"],
			Evidence:   code,
			CWE:        "CWE-79",
			Severity:   "Medium",
		}
		return poc
	}
	if strings.Contains(q.metadata["type"], "inATTR") {
		if vds {
			code := CodeView(resbody, q.metadata["payload"])
			poc := &model.PoC{
				Type:       "V",
				InjectType: q.metadata["type"],
				Method:     q.request.Method,
				Data:       q.request.URL.String(),
				Param:      q.metadata["param"],
				Payload:    q.metadata["payload"],
				Evidence:   code,
				CWE:        "CWE-83",
				Severity:   "High",
			}
			return poc
		}
		if vrs {
			code := CodeView(resbody, q.metadata["payload"])
			poc := &model.PoC{
				Type:       "R",
				InjectType: q.metadata["type"],
				Method:     q.request.Method,
				Data:       q.request.URL.String(),
				Param:      q.metadata["param"],
				Payload:    q.metadata["payload"],
				Evidence:   code,
				CWE:        "CWE-83",
				Severity:   "Medium",
			}
			return poc
		}
		return nil
	}
	if vds {
		code := CodeView(resbody, q.metadata["payload"])
		poc := &model.PoC{
			Type:       "V",
			InjectType: q.metadata["type"],
			Method:     q.request.Method,
			Data:       q.request.URL.String(),
			Param:      q.metadata["param"],
			Payload:    q.metadata["payload"],
			Evidence:   code,
			CWE:        "CWE-79",
			Severity:   "High",
		}
		return poc

	}
	if vrs {
		code := CodeView(resbody, q.metadata["payload"])

		poc := &model.PoC{
			Type:       "R",
			InjectType: q.metadata["type"],
			Method:     q.request.Method,
			Data:       q.request.URL.String(),
			Param:      q.metadata["param"],
			Payload:    q.metadata["payload"],
			Evidence:   code,
			CWE:        "CWE-79",
			Severity:   "Medium",
		}
		return poc

	}
	return nil
}

func checkVStatus(vStatus map[string]bool) bool {
	for k, v := range vStatus {
		if k != "pleasedonthaveanamelikethis_plz_plz" {
			if !v {
				return false
			}
		} else {
			return false
		}
	}
	return true
}
