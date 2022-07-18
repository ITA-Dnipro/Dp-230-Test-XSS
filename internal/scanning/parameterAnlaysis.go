package scanning

import (
	"io/ioutil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"go.uber.org/zap"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/optimization"
)

func setP(p url.Values, name string) url.Values {
	if p.Get(name) == "" {
		p.Set(name, "")
	}
	return p
}

// ParameterAnalysis is check reflected and mining params
func ParameterAnalysis(log *zap.Logger, target string, options model.Options) map[string][]string {
	u, err := url.Parse(target)
	if err != nil {
		return map[string][]string{}
	}

	p, _ := url.ParseQuery(u.RawQuery)

	if options.Mining {
		// Param mining with Gf-Patterins
		for _, gfParam := range GetGfXSS() {
			if gfParam != "" {
				p = setP(p, gfParam)
			}
		}
	}
	if options.FindingDOM {
		for _, domParam := range getDOMParams(target, options) {
			if domParam != "" {
				p = setP(p, domParam)
			}
		}
	}

	params := validatedParams(target, p, options)

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

func getDOMParams(target string, options model.Options) []string {
	p := make([]string, 0)

	treq := optimization.GenerateNewRequest(target, "", options)
	bodyStr, _, _, _, err := SendReq(treq, "", time.Duration(options.Timeout)*time.Second)
	if err != nil {
		return p
	}

	body := ioutil.NopCloser(strings.NewReader(string(bodyStr)))
	defer body.Close()

	doc, err := goquery.NewDocumentFromReader(body)
	if err == nil {
		return p
	}

	doc.Find("input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		p = append(p, name)
	})
	doc.Find("textarea").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		p = append(p, name)
	})
	doc.Find("select").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		p = append(p, name)
	})
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		action, _ := s.Attr("action")
		if strings.HasPrefix(action, "/") || strings.HasPrefix(action, "?") { // assuming this is a relative URL
			url, _ := url.Parse(action)
			query := url.Query()
			for aParam := range query {
				p = append(p, aParam)
			}

		}
	})
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		href, _ := s.Attr("href")
		if strings.HasPrefix(href, "/") || strings.HasPrefix(href, "?") { // assuming this is a relative URL
			url, _ := url.Parse(href)
			query := url.Query()
			for aParam := range query {
				p = append(p, aParam)
			}

		}
	})
	return p
}

func validatedParams(target string, p url.Values, options model.Options) map[string][]string {
	params := make(map[string][]string)
	var wgg sync.WaitGroup
	concurrency := options.Concurrence
	paramsQue := make(chan string)
	miningDictCount := 0
	mutex := &sync.Mutex{}
	for i := 0; i < concurrency; i++ {
		wgg.Add(1)
		go func() {
			for k := range paramsQue {
				tempURL, _ := optimization.MakeRequestQuery(target, k, "DalFox", "PA", "toAppend", "NaN", options)
				var code string
				resbody, _, _, vrs, _ := SendReq(tempURL, "DalFox", time.Duration(options.Timeout)*time.Second)
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
								_, _, _, vrs, _ := SendReq(turl, "dalfox"+char, time.Duration(options.Timeout)*time.Second)
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
			wgg.Done()
		}()
	}

	for v := range p {
		paramsQue <- v
	}

	close(paramsQue)
	wgg.Wait()
	return params
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
