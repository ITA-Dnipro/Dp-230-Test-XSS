package scanning

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"go.uber.org/zap"

	"test/internal/model"
	"test/internal/optimization"
)

//TODO: refactor
// Scan is main scanning function
func Scan(log *zap.Logger, target string, options model.Options, sid string) (model.Result, error) {
	var scanResult model.Result

	log.Info("SYSTEM", zap.String("url", target))

	// query is XSS payloads
	query := make(map[*http.Request]map[string]string)

	if _, err := url.Parse(target); err != nil {
		log.Error("SYSTEM Not running invalid target", zap.String("url", target), zap.Error(err))
		return scanResult, err
	}

	log.Info("SYSTEM Waiting for analysis")
	// set up a rate limit
	// TODO: remove magic number
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))
	policy := StaticAnalysis(target, options, rl)
	params := ParameterAnalysis(log, target, options, rl)

	for k, v := range policy {
		if len(v) != 0 {
			if k == "BypassCSP" {
				log.Info("WEAK Policy", zap.String("name", k), zap.String("value", v))
			} else {
				log.Info("Policy", zap.String("name", k), zap.String("value", v))
			}
		}
	}

	for k, v := range params {
		if len(v) != 0 {
			code, vv := v[len(v)-1], v[:len(v)-1]
			char := strings.Join(vv, "  ")
			//x, a = a[len(a)-1], a[:len(a)-1]
			log.Info("Reflected", zap.String("param", k), zap.String("char", char), zap.String("code", code))
		}
	}

	// XSS Scanning
	log.Info("SYSTEM  Generate XSS payload and optimization.Optimization..")
	// optimization.Optimization..

	/*
		k: parama name
		v: pattern [injs, inhtml, ' < > ]
		av: reflected type, valid char
	*/

	if isAllowType(policy["Content-Type"]) {
		// Set common payloads
		cp, cpd := getUrlValues(target, options.Data)

		for v := range cp {
			arc := optimization.SetPayloadValue(getCommonPayload(), options)
			for _, avv := range arc {
				encoders := []string{
					"NaN",
					"urlEncode",
					"urlDoubleEncode",
					"htmlEncode",
				}
				for _, encoder := range encoders {
					tq, tm := optimization.MakeRequestQuery(target, v, avv, "inHTML-URL", "toAppend", encoder, options)
					query[tq] = tm
				}
			}
		}

		for v := range cpd {
			arc := optimization.SetPayloadValue(getCommonPayload(), options)
			for _, avv := range arc {
				encoders := []string{
					"NaN",
					"urlEncode",
					"urlDoubleEncode",
					"htmlEncode",
				}
				for _, encoder := range encoders {
					tq, tm := optimization.MakeRequestQuery(target, v, avv, "inHTML-FORM", "toAppend", encoder, options)
					query[tq] = tm
				}
			}
		}

		// Set param base xss
		for k, v := range params {
			ptype := ""
			chars := GetSpecialChar()
			var badchars []string

			for _, av := range v {
				if indexOf(av, chars) == -1 {
					badchars = append(badchars, av)
				}
				if strings.Contains(av, "PTYPE:") {
					ptype = GetPType(av)
				}

				if strings.Contains(av, "Injected:") {
					// Injected pattern
					injectedPoint := strings.Split(av, "/")
					injectedPoint = injectedPoint[1:]
					injectedChars := params[k][:len(params[k])-1]
					for _, ip := range injectedPoint {
						var arr []string
						if strings.Contains(ip, "inJS") {
							checkInJS := false
							if strings.Contains(ip, "double") {
								for _, injectedChar := range injectedChars {
									if strings.Contains(injectedChar, "\"") {
										checkInJS = true
									}
								}
							}
							if strings.Contains(ip, "single") {
								for _, injectedChar := range injectedChars {
									if strings.Contains(injectedChar, "'") {
										checkInJS = true
									}
								}
							}
							if checkInJS {
								arr = optimization.SetPayloadValue(getInJsPayload(ip), options)
							} else {
								arr = optimization.SetPayloadValue(getInJsBreakScriptPayload(ip), options)
							}
						}
						if strings.Contains(ip, "inHTML") {
							arr = optimization.SetPayloadValue(getHTMLPayload(ip), options)
						}
						if strings.Contains(ip, "inATTR") {
							arr = optimization.SetPayloadValue(getAttrPayload(ip), options)
						}
						for _, avv := range arr {
							if optimization.Optimization(avv, badchars) {
								encoders := []string{
									"NaN",
									"urlEncode",
									"urlDoubleEncode",
									"htmlEncode",
								}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, avv, ip+ptype, "toAppend", encoder, options)
									query[tq] = tm
								}
							}
						}
					}
				}
			}
		}
	} else {
		log.Info("SYSTEM, It does not test except customized payload.")
	}

	log.Info("SYSTEM, Start XSS Scanning.. ", zap.Int("workers count", options.Concurrence), zap.Int("queries count", len(query)))

	wp := NewWorkerPool(10)
	go wp.GenerateFrom(query)
	go wp.Run(context.Background())
	for res := range wp.Results() {
		if res != nil {
			scanResult.PoCs = append(scanResult.PoCs, *res)
		}
	}

	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)

	return scanResult, nil
}

func getUrlValues(target, data string) (cp, cpd url.Values) {
	cu, err := url.Parse(target)
	if err == nil {
		if data == "" {
			cp, _ = url.ParseQuery(cu.RawQuery)
			if len(cp) == 0 {
				cp, _ = url.ParseQuery(cu.Fragment)
			}
		} else {
			cp, _ = url.ParseQuery(cu.RawQuery)
			cpd, _ = url.ParseQuery(data)
		}
	}
	return cp, cpd
}

// Initialize is init for model.Options
func Initialize(target model.Target, options model.Options) model.Options {
	stime := time.Now()
	newOptions := model.Options{
		Header:           []string{},
		Cookie:           "",
		CustomAlertValue: "1",
		CustomAlertType:  "none",
		Data:             "",
		UserAgent:        "",
		ProxyAddress:     "",
		Timeout:          10,
		Concurrence:      100,
		Delay:            0,
		Mining:           true,
		FindingDOM:       true,
		Method:           "GET",
		CookieFromRaw:    "",
		StartTime:        stime,
		UseHeadless:      true,
		UseDeepDXSS:      false,
	}
	if target.Method != "" {
		newOptions.Method = target.Method
	}
	if options.Cookie != "" {
		newOptions.Cookie = options.Cookie
	}
	if len(options.Header) > 0 {
		for _, v := range options.Header {
			newOptions.Header = append(newOptions.Header, v)
		}
	}
	if options.CustomAlertValue != "" {
		newOptions.CustomAlertValue = options.CustomAlertValue
	}
	if options.CustomAlertType != "" {
		newOptions.CustomAlertType = options.CustomAlertType
	}
	if options.Data != "" {
		newOptions.Data = options.Data
	}
	if options.UserAgent != "" {
		newOptions.UserAgent = options.UserAgent
	}
	if options.ProxyAddress != "" {
		newOptions.ProxyAddress = options.ProxyAddress
	}

	if options.Timeout != 0 {
		newOptions.Timeout = options.Timeout
	}
	if options.Concurrence != 0 {
		newOptions.Concurrence = options.Concurrence
	}
	if options.Delay != 0 {
		newOptions.Delay = options.Delay
	}

	if options.Mining != false {
		newOptions.Mining = options.Mining
	}
	if options.FindingDOM != false {
		newOptions.FindingDOM = options.FindingDOM
	}

	if options.UseHeadless == false {
		newOptions.UseHeadless = false
	}
	if options.UseDeepDXSS == true {
		newOptions.UseDeepDXSS = true
	}

	return newOptions
}

// NewScan is dalfox single scan in lib
func NewScan(log *zap.Logger, target model.Target) (model.Result, error) {
	newOptions := Initialize(target, target.Options)
	modelResult, err := Scan(log, target.URL, newOptions, "Single")
	result := model.Result{
		Logs:      modelResult.Logs,
		PoCs:      modelResult.PoCs,
		Duration:  modelResult.Duration,
		StartTime: modelResult.StartTime,
		EndTime:   modelResult.EndTime,
	}
	return result, err
}
