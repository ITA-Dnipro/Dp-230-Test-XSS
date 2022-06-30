package scanning

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"test/internal/model"
	"test/internal/optimization"
	"test/internal/verification"

	"github.com/PuerkitoBio/goquery"
	"go.uber.org/zap"
)

func setP(p url.Values, name string, options model.Options) url.Values {
	if p.Get(name) == "" {
		p.Set(name, "")
	}
	return p
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(log *zap.Logger, target string, options model.Options, rl *rateLimiter) map[string][]string {
	miningCheckerLine := 0
	u, err := url.Parse(target)
	params := make(map[string][]string)
	if err != nil {
		return params
	}

	p, _ := url.ParseQuery(u.RawQuery)

	if options.Mining {
		tempURL, _ := optimization.MakeRequestQuery(target, "pleasedonthaveanamelikethis_plz_plz", "DalFox", "PA", "toAppend", "NaN", options)
		rl.Block(tempURL.Host)
		resBody, _, _, vrs, _ := SendReq(tempURL, "DalFox", options)
		if vrs {
			_, lineSum := verification.VerifyReflectionWithLine(resBody, "DalFox")
			miningCheckerLine = lineSum
		}

		// Add UniqParam to Mining output
		if len(options.UniqParam) > 0 {
			for _, selectedParam := range options.UniqParam {
				p = setP(p, selectedParam, options)
			}
		}

		// Param mining with Gf-Patterins
		if options.MiningWordlist == "" {
			for _, gfParam := range GetGfXSS() {
				if gfParam != "" {
					p = setP(p, gfParam, options)
				}
			}
		}

	}
	if options.FindingDOM {
		treq := optimization.GenerateNewRequest(target, "", options)
		//treq, terr := http.NewRequest("GET", target, nil)
		if treq != nil {
			transport := getTransport(options)
			t := options.Timeout
			client := &http.Client{
				Timeout:   time.Duration(t) * time.Second,
				Transport: transport,
			}

			if !options.FollowRedirect {
				client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
					//return errors.New("Follow redirect") // or maybe the error from the request
					return nil
				}
			}

			tres, err := client.Do(treq)
			if err == nil {
				defer tres.Body.Close()
				var reader io.ReadCloser
				switch tres.Header.Get("Content-Encoding") {
				case "gzip":
					reader, err = gzip.NewReader(tres.Body)
					if err != nil {
						reader = tres.Body
					}
					defer reader.Close()
				default:
					reader = tres.Body
				}
				bodyString, err := ioutil.ReadAll(reader)
				if err == nil {
					body := ioutil.NopCloser(strings.NewReader(string(bodyString)))
					defer body.Close()
					doc, err := goquery.NewDocumentFromReader(body)
					if err == nil {
						count := 0
						doc.Find("input").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p = setP(p, name, options)
							count = count + 1
						})
						doc.Find("textarea").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p = setP(p, name, options)
							count = count + 1
						})
						doc.Find("select").Each(func(i int, s *goquery.Selection) {
							name, _ := s.Attr("name")
							p = setP(p, name, options)
							count = count + 1
						})
						doc.Find("form").Each(func(i int, s *goquery.Selection) {
							action, _ := s.Attr("action")
							if strings.HasPrefix(action, "/") || strings.HasPrefix(action, "?") { // assuming this is a relative URL
								url, _ := url.Parse(action)
								query := url.Query()
								for aParam := range query {
									p = setP(p, aParam, options)
									count = count + 1
								}

							}
						})
						doc.Find("a").Each(func(i int, s *goquery.Selection) {
							href, _ := s.Attr("href")
							if strings.HasPrefix(href, "/") || strings.HasPrefix(href, "?") { // assuming this is a relative URL
								url, _ := url.Parse(href)
								query := url.Query()
								for aParam := range query {
									p = setP(p, aParam, options)
									count = count + 1
								}

							}
						})
						log.Info("Found ", zap.Int("testing point in DOM base parameter mining: ", count))
					}
				}
			}
		}
	}

	// Testing URL Params
	var wgg sync.WaitGroup
	concurrency := options.Concurrence
	paramsQue := make(chan string)
	miningDictCount := 0
	waf := false
	wafName := ""
	mutex := &sync.Mutex{}
	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			for k := range paramsQue {
				if optimization.CheckInspectionParam(options, k) {
					log.Debug("Mining URL scan to ", zap.String("url", k))
					tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA", "toAppend", "NaN", options)
					var code string
					rl.Block(tempURL.Host)
					resbody, resp, _, vrs, err := SendReq(tempURL, "DalFox", options)
					if err == nil {
						wafCheck, wafN := checkWAF(resp.Header, resbody)
						if wafCheck {
							mutex.Lock()
							if !waf {
								waf = true
								wafName = wafN
								if options.WAFEvasion {
									options.Concurrence = 1
									options.Delay = 3
									log.Info("Set worker=1, delay=3s for WAF-Evasion")
								}
							}
							mutex.Unlock()
						}
					}
					_, lineSum := verification.VerifyReflectionWithLine(resbody, "DalFox")
					if miningCheckerLine == lineSum {
						//vrs = false
						//(#354) It can cause a lot of misconceptions. removed it.
					}
					if vrs {
						code = CodeView(resbody, "DalFox")
						code = code[:len(code)-5]
						pointer := optimization.Abstraction(resbody, "DalFox")
						smap := "Injected: "
						tempSmap := make(map[string]int)

						for _, v := range pointer {
							if tempSmap[v] == 0 {
								tempSmap[v] = 1
							} else {
								tempSmap[v] = tempSmap[v] + 1
							}
						}
						for k, v := range tempSmap {
							smap = smap + "/" + k + "(" + strconv.Itoa(v) + ")"
						}
						mutex.Lock()
						miningDictCount = miningDictCount + 1
						params[k] = append(params[k], "PTYPE: URL")
						params[k] = append(params[k], smap)
						mutex.Unlock()
						var wg sync.WaitGroup
						chars := GetSpecialChar()
						for _, c := range chars {
							wg.Add(1)
							char := c
							go func() {
								defer wg.Done()
								encoders := []string{
									"NaN",
									"urlEncode",
									"urlDoubleEncode",
									"htmlEncode",
								}

								for _, encoder := range encoders {
									turl, _ := optimization.MakeRequestQuery(target, k, "dalfox"+char, "PA-URL", "toAppend", encoder, options)
									rl.Block(tempURL.Host)
									_, _, _, vrs, _ := SendReq(turl, "dalfox"+char, options)
									if vrs {
										mutex.Lock()
										params[k] = append(params[k], char)
										mutex.Unlock()
									}
								}
							}()
						}
						wg.Wait()
						params[k] = uniqueStringSlice(params[k])
						params[k] = append(params[k], code)
					}
				}
			}
			wgg.Done()
		}()
	}

	for v := range p {
		paramsQue <- v
	}

	close(paramsQue)
	wgg.Wait()

	if miningDictCount != 0 {
		log.Info(" Found testing point in Dictionary base paramter mining", zap.Int("dictionary count", miningDictCount))
	}
	if waf {
		log.Info("Found WAF: ", zap.String("wafName", wafName))
		options.WAF = true
	}
	return params
}

// GetPType is Get Parameter Type
func GetPType(av string) string {
	if strings.Contains(av, "PTYPE: URL") {
		return "-URL"
	}
	if strings.Contains(av, "PTYPE: FORM") {
		return "-FORM"
	}
	return ""
}

// UniqueStringSlice is remove duplicated data in String Slice(array)
func uniqueStringSlice(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
