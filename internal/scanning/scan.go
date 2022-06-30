package scanning

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	voltFile "github.com/hahwul/volt/file"
	"go.uber.org/zap"

	"test/internal/model"
	"test/internal/optimization"
	"test/internal/verification"
)

//TODO: refactor
// Scan is main scanning function
func Scan(log *zap.Logger, target string, options model.Options, sid string) (model.Result, error) {
	var scanResult model.Result
	mutex := &sync.Mutex{}
	options.ScanResult = scanResult

	scanObject := model.Scan{
		ScanID: sid,
		URL:    target,
	}

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
	// durls is url for dom xss
	var durls []string

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

	vStatus := make(map[string]bool)
	vStatus["pleasedonthaveanamelikethis_plz_plz"] = false

	if !options.OnlyDiscovery {
		// XSS Scanning
		log.Info("SYSTEM  Generate XSS payload and optimization.Optimization..")
		// optimization.Optimization..

		/*
			k: parama name
			v: pattern [injs, inhtml, ' < > ]
			av: reflected type, valid char
		*/

		// set vStatus
		for k := range params {
			vStatus[k] = false
		}

		// Custom Payload
		if isAllowType(policy["Content-Type"]) && options.CustomPayloadFile != "" {
			ff, err := voltFile.ReadLinesOrLiteral(options.CustomPayloadFile)
			if err != nil {
				log.Info("SYSTEM Custom XSS payload load fail..")
			} else {
				for _, customPayload := range ff {
					if customPayload != "" {
						for k, v := range params {
							if optimization.CheckInspectionParam(options, k) {
								ptype := ""
								for _, av := range v {
									if strings.Contains(av, "PTYPE:") {
										ptype = GetPType(av)
									}
								}
								encoders := []string{
									"NaN",
									"urlEncode",
									"urlDoubleEncode",
									"htmlEncode",
								}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, customPayload, "inHTML"+ptype, "toAppend", encoder, options)
									query[tq] = tm
								}
							}
						}
					}
				}
				log.Info("SYSTEM Added your custom xss payload", zap.Int("payloads count", len(ff)))
			}
		}

		if isAllowType(policy["Content-Type"]) && !options.OnlyCustomPayload {
			// Set common payloads
			cu, err := url.Parse(target)
			var cp url.Values
			var cpd url.Values
			var cpArr []string
			var cpdArr []string
			hashParam := false
			if err == nil {
				if options.Data == "" {
					cp, _ = url.ParseQuery(cu.RawQuery)
					if len(cp) == 0 {
						cp, _ = url.ParseQuery(cu.Fragment)
					}
				} else {
					cp, _ = url.ParseQuery(cu.RawQuery)
					cpd, _ = url.ParseQuery(options.Data)
				}
			}

			for v := range cp {
				if optimization.CheckInspectionParam(options, v) {
					cpArr = append(cpArr, v)
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
			}

			for v := range cpd {
				if optimization.CheckInspectionParam(options, v) {
					cpdArr = append(cpdArr, v)
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
			}
			// DOM XSS payload
			var dlst []string
			if options.UseHeadless {
				if options.UseDeepDXSS {
					dlst = getDeepDOMXSPayload()
				} else {
					dlst = getDOMXSSPayload()
				}
				dpayloads := optimization.SetPayloadValue(dlst, options)
				for v := range cp {
					if optimization.CheckInspectionParam(options, v) {
						// loop payload list
						if len(params[v]) == 0 {
							for _, dpayload := range dpayloads {
								var durl string
								u, _ := url.Parse(target)
								dp, _ := url.ParseQuery(u.RawQuery)
								if hashParam {
									dp, _ = url.ParseQuery(u.Fragment)
									dp.Set(v, dpayload)
									u.Fragment, _ = url.QueryUnescape(dp.Encode())
								} else {
									dp.Set(v, dpayload)
									u.RawQuery = dp.Encode()
								}
								durl = u.String()
								durls = append(durls, durl)
							}
						}
					}
				}
				for v := range cpd {
					if optimization.CheckInspectionParam(options, v) {
						// loop payload list
						if len(params[v]) == 0 {
							for _, dpayload := range dpayloads {
								var durl string
								u, _ := url.Parse(target)
								dp, _ := url.ParseQuery(u.RawQuery)
								if hashParam {
									dp, _ = url.ParseQuery(u.Fragment)
									dp.Set(v, dpayload)
									u.Fragment, _ = url.QueryUnescape(dp.Encode())
								} else {
									dp.Set(v, dpayload)
									u.RawQuery = dp.Encode()
								}
								durl = u.String()
								durls = append(durls, durl)
							}
						}
					}
				}
			}
			// Set param base xss
			for k, v := range params {
				if optimization.CheckInspectionParam(options, k) {
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
					// common XSS for new param
					arc := optimization.SetPayloadValue(getCommonPayload(), options)
					for _, avv := range arc {
						if !containsFromArray(cpArr, k) {
							if optimization.Optimization(avv, badchars) {
								encoders := []string{
									"NaN",
									"urlEncode",
									"urlDoubleEncode",
									"htmlEncode",
								}
								for _, encoder := range encoders {
									tq, tm := optimization.MakeRequestQuery(target, k, avv, "inHTML"+ptype, "toAppend", encoder, options)
									query[tq] = tm
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
		queryCount := 0

		// make waiting group
		var wg sync.WaitGroup
		// set concurrency
		concurrency := options.Concurrence
		// make reqeust channel
		queries := make(chan Queries)

		if options.UseHeadless {
			// start DOM XSS checker
			wg.Add(1)
			go func() {
				dconcurrency := options.Concurrence / 2
				if dconcurrency < 1 {
					dconcurrency = 1
				}
				if dconcurrency > 10 {
					dconcurrency = 10
				}
				dchan := make(chan string)
				var wgg sync.WaitGroup
				for i := 0; i < dconcurrency; i++ {
					wgg.Add(1)
					go func() {
						for v := range dchan {
							if CheckXSSWithHeadless(v, options) {
								mutex.Lock()
								log.Info("VULN Triggered XSS Payload (found dialog in headless)")
								poc := model.PoC{
									Type:       "V",
									InjectType: "headless",
									Method:     "GET",
									Data:       v,
									Param:      "",
									Payload:    "",
									Evidence:   "",
									CWE:        "CWE-79",
									Severity:   "High",
									PoCType:    options.PoCType,
								}

								scanObject.Results = append(scanObject.Results, poc)
								scanResult.PoCs = append(scanResult.PoCs, poc)
								mutex.Unlock()
							}
							queryCount = queryCount + 1
						}
						wgg.Done()
					}()
				}
				for _, dchanData := range durls {
					dchan <- dchanData
				}
				close(dchan)
				wgg.Wait()
				wg.Done()
			}()
		}
		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func() {
				for reqJob := range queries {
					if checkVStatus(vStatus) {
						// if when all param found xss, break. (for passing speed up)
						continue
					}
					// quires.request : http.Request
					// queries.metadata : map[string]string
					k := reqJob.request
					v := reqJob.metadata
					checkVtype := false
					if checkPType(v["type"]) {
						checkVtype = true
					}

					if vStatus[v["param"]] == false || checkVtype {
						rl.Block(k.Host)
						resbody, _, vds, vrs, err := SendReq(k, v["payload"], options)
						abs := optimization.Abstraction(resbody, v["payload"])
						if vrs {
							if !containsFromArray(abs, v["type"]) && !strings.Contains(v["type"], "inHTML") {
								vrs = false
							}
						}
						if err == nil {
							if checkPType(v["type"]) {
								if strings.Contains(v["type"], "inJS") {
									if vrs {
										protected := false
										if verification.VerifyReflection(resbody, "\\"+v["payload"]) {
											if !strings.Contains(v["payload"], "\\") {
												protected = true
											}
										}
										if !protected {
											if vStatus[v["param"]] == false {
												if options.UseHeadless {
													if CheckXSSWithHeadless(k.URL.String(), options) {
														mutex.Lock()
														log.Info("VULN Triggered XSS Payload (found dialog in headless)")
														poc := model.PoC{
															Type:       "V",
															InjectType: v["type"],
															Method:     k.Method,
															Data:       k.URL.String(),
															Param:      v["param"],
															Payload:    "",
															Evidence:   "",
															CWE:        "CWE-79",
															Severity:   "High",
															PoCType:    options.PoCType,
														}
														poc.Data = MakePoC(poc.Data, k, options)

														vStatus[v["param"]] = true

														scanObject.Results = append(scanObject.Results, poc)
														scanResult.PoCs = append(scanResult.PoCs, poc)
														mutex.Unlock()
													} else {
														mutex.Lock()
														poc := model.PoC{
															Type:       "R",
															InjectType: v["type"],
															Method:     k.Method,
															Data:       k.URL.String(),
															Param:      v["param"],
															Payload:    "",
															Evidence:   "",
															CWE:        "CWE-79",
															Severity:   "Medium",
															PoCType:    options.PoCType,
														}
														poc.Data = MakePoC(poc.Data, k, options)

														scanObject.Results = append(scanObject.Results, poc)
														scanResult.PoCs = append(scanResult.PoCs, poc)
														mutex.Unlock()
													}
												} else {
													mutex.Lock()
													code := CodeView(resbody, v["payload"])
													log.Info("WEAK Reflected Payload in JS: ", zap.String("param", v["param"]), zap.String("payload", v["payload"]))
													poc := model.PoC{
														Type:       "R",
														InjectType: v["type"],
														Method:     k.Method,
														Data:       k.URL.String(),
														Param:      v["param"],
														Payload:    v["payload"],
														Evidence:   code,
														CWE:        "CWE-79",
														Severity:   "Medium",
														PoCType:    options.PoCType,
													}
													poc.Data = MakePoC(poc.Data, k, options)

													scanObject.Results = append(scanObject.Results, poc)
													scanResult.PoCs = append(scanResult.PoCs, poc)
													mutex.Unlock()
												}
											}
										}
									}
								} else if strings.Contains(v["type"], "inATTR") {
									if vds {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											poc := model.PoC{
												Type:       "V",
												InjectType: v["type"],
												Method:     k.Method,
												Data:       k.URL.String(),
												Param:      v["param"],
												Payload:    v["payload"],
												Evidence:   code,
												CWE:        "CWE-83",
												Severity:   "High",
												PoCType:    options.PoCType,
											}
											poc.Data = MakePoC(poc.Data, k, options)

											vStatus[v["param"]] = true
											scanObject.Results = append(scanObject.Results, poc)
											scanResult.PoCs = append(scanResult.PoCs, poc)
										}
										mutex.Unlock()
									} else if vrs {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											poc := model.PoC{
												Type:       "R",
												InjectType: v["type"],
												Method:     k.Method,
												Data:       k.URL.String(),
												Param:      v["param"],
												Payload:    v["payload"],
												Evidence:   code,
												CWE:        "CWE-83",
												Severity:   "Medium",
												PoCType:    options.PoCType,
											}
											poc.Data = MakePoC(poc.Data, k, options)

											scanObject.Results = append(scanObject.Results, poc)
											scanResult.PoCs = append(scanResult.PoCs, poc)
										}
										mutex.Unlock()
									}
								} else {
									if vds {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])
											poc := model.PoC{
												Type:       "V",
												InjectType: v["type"],
												Method:     k.Method,
												Data:       k.URL.String(),
												Param:      v["param"],
												Payload:    v["payload"],
												Evidence:   code,
												CWE:        "CWE-79",
												Severity:   "High",
												PoCType:    options.PoCType,
											}
											poc.Data = MakePoC(poc.Data, k, options)

											vStatus[v["param"]] = true

											scanObject.Results = append(scanObject.Results, poc)
											scanResult.PoCs = append(scanResult.PoCs, poc)
										}
										mutex.Unlock()
									} else if vrs {
										mutex.Lock()
										if vStatus[v["param"]] == false {
											code := CodeView(resbody, v["payload"])

											poc := model.PoC{
												Type:       "R",
												InjectType: v["type"],
												Method:     k.Method,
												Data:       k.URL.String(),
												Param:      v["param"],
												Payload:    v["payload"],
												Evidence:   code,
												CWE:        "CWE-79",
												Severity:   "Medium",
												PoCType:    options.PoCType,
											}
											poc.Data = MakePoC(poc.Data, k, options)

											scanObject.Results = append(scanObject.Results, poc)
											scanResult.PoCs = append(scanResult.PoCs, poc)
										}
										mutex.Unlock()
									}
								}
							}
						}
					}
					mutex.Lock()
					queryCount = queryCount + 1
					mutex.Unlock()
				}
				wg.Done()
			}()
		}

		// Send testing query to quires channel
		for k, v := range query {
			queries <- Queries{
				request:  k,
				metadata: v,
			}
		}
		close(queries)
		wg.Wait()
	}

	options.Scan[sid] = scanObject
	scanResult.EndTime = time.Now()
	scanResult.Duration = scanResult.EndTime.Sub(scanResult.StartTime)

	return scanResult, nil
}

// Initialize is init for model.Options
func Initialize(target model.Target, options model.Options) model.Options {
	stime := time.Now()
	newOptions := model.Options{
		IsLibrary:         true,
		Header:            []string{},
		Cookie:            "",
		UniqParam:         []string{},
		BlindURL:          "",
		CustomPayloadFile: "",
		CustomAlertValue:  "1",
		CustomAlertType:   "none",
		Data:              "",
		UserAgent:         "",
		OutputFile:        "",
		Format:            "plain",
		FoundAction:       "",
		FoundActionShell:  "bash",
		ProxyAddress:      "",
		Grep:              "",
		IgnoreReturn:      "",
		IgnoreParams:      []string{},
		Timeout:           10,
		TriggerMethod:     "GET",
		Concurrence:       100,
		Delay:             0,
		OnlyDiscovery:     false,
		OnlyCustomPayload: false,
		Silence:           true,
		FollowRedirect:    false,
		Scan:              make(map[string]model.Scan),
		Mining:            true,
		MiningWordlist:    "",
		FindingDOM:        true,
		NoColor:           true,
		Method:            "GET",
		NoSpinner:         true,
		NoBAV:             false,
		NoGrep:            false,
		Debug:             false,
		CookieFromRaw:     "",
		StartTime:         stime,
		MulticastMode:     false,
		RemotePayloads:    "",
		RemoteWordlists:   "",
		OnlyPoC:           "",
		OutputAll:         false,
		PoCType:           "",
		Sequence:          -1,
		UseHeadless:       true,
		UseDeepDXSS:       false,
		WAFEvasion:        false,
	}
	if len(options.UniqParam) > 0 {
		for _, v := range options.UniqParam {
			newOptions.UniqParam = append(newOptions.UniqParam, v)
		}
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
	if options.BlindURL != "" {
		newOptions.BlindURL = options.BlindURL
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
	if options.Grep != "" {
		newOptions.Grep = options.Grep
	}
	if options.IgnoreReturn != "" {
		newOptions.IgnoreReturn = options.IgnoreReturn
	}
	if len(options.IgnoreParams) > 0 {
		for _, v := range options.IgnoreParams {
			newOptions.IgnoreParams = append(newOptions.IgnoreParams, v)
		}
	}
	if options.Trigger != "" {
		newOptions.Trigger = options.Trigger
	}
	if options.TriggerMethod != "" {
		newOptions.TriggerMethod = options.TriggerMethod
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
	if options.OnlyDiscovery != false {
		newOptions.OnlyDiscovery = options.OnlyDiscovery
	}
	if options.FollowRedirect != false {
		newOptions.FollowRedirect = options.FollowRedirect
	}
	if options.Mining != false {
		newOptions.Mining = options.Mining
	}
	if options.FindingDOM != false {
		newOptions.FindingDOM = options.FindingDOM
	}
	if options.NoBAV != false {
		newOptions.NoBAV = options.NoBAV
	}
	if options.NoGrep != false {
		newOptions.NoGrep = options.NoGrep
	}
	if options.RemotePayloads != "" {
		newOptions.RemotePayloads = options.RemotePayloads
	}
	if options.RemoteWordlists != "" {
		newOptions.RemoteWordlists = options.RemoteWordlists
	}
	if options.PoCType != "" {
		newOptions.PoCType = options.PoCType
	}
	if options.CustomPayloadFile != "" {
		newOptions.CustomPayloadFile = options.CustomPayloadFile
	}
	if options.OutputFile != "" {
		newOptions.OutputFile = options.OutputFile
	}
	if options.FoundAction != "" {
		newOptions.FoundAction = options.FoundAction
	}
	if options.FoundActionShell != "" {
		newOptions.FoundActionShell = options.FoundActionShell
	}
	if options.OutputFile != "" {
		newOptions.OutputFile = options.OutputFile
	}
	if options.OnlyCustomPayload == true {
		newOptions.OnlyCustomPayload = true
	}
	if options.UseHeadless == false {
		newOptions.UseHeadless = false
	}
	if options.UseDeepDXSS == true {
		newOptions.UseDeepDXSS = true
	}
	if options.WAFEvasion == true {
		newOptions.WAFEvasion = true
	}
	if options.Sequence != -1 {
		newOptions.Sequence = options.Sequence
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
