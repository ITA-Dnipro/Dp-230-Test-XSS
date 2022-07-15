package scanning

import (
	"context"
	"errors"

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

	if _, err := url.Parse(target); err != nil {
		log.Error("SYSTEM Not running invalid target", zap.String("url", target), zap.Error(err))
		return scanResult, err
	}

	log.Info("SYSTEM Waiting for analysis")
	// set up a rate limit
	rl := newRateLimiter(time.Duration(options.Delay * 1000000))

	policy := StaticAnalysis(target, options, rl)

	if !isAllowType(policy["Content-Type"]) {
		log.Error("SYSTEM Not running not allow target policy", zap.String("url", target), zap.String("policy", policy["Content-Type"]))
		return scanResult, errors.New("not allow policy")
	}

	params := ParameterAnalysis(log, target, options, rl)

	// XSS Scanning
	log.Info("SYSTEM  Generate XSS payload and optimization.Optimization..")

	// query is XSS payloads
	query := make([]Queries, 0)

	uq := getUrlQueries(target, options)
	query = append(query, uq...)
	up := getParamAnalysisQueries(target, params, options)
	query = append(query, up...)

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

func getUrlQueries(target string, options model.Options) []Queries {
	cp, cpd := getUrlValues(target, options.Data)

	queries := make([]Queries, 0)

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
				queries = append(queries, Queries{request: tq, metadata: tm})
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
				queries = append(queries, Queries{request: tq, metadata: tm})
			}
		}
	}
	return queries
}

func getParamAnalysisQueries(target string, params map[string][]string, options model.Options) []Queries {
	queries := make([]Queries, 0)
	//Set param base xss
	for k, v := range params {
		ptype := ""
		chars := GetSpecialChar()
		var badchars []string

		for _, av := range v {
			if !strings.Contains(av, "Injected:") {
				continue
			}

			if indexOf(av, chars) == -1 {
				badchars = append(badchars, av)
			}
			if strings.Contains(av, "PTYPE:") {
				ptype = GetPType(av)
			}

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
							queries = append(queries, Queries{request: tq, metadata: tm})
						}
					}
				}
			}
		}
	}
	return queries
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
