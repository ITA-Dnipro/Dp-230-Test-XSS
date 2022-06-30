package main

import (
	"fmt"
	"time"

	"go.uber.org/zap"

	"test/internal/model"
	"test/internal/scanning"
)

func main() {
	urls := []string{
		"https://xss-game.appspot.com/level1/frame",

		"http://sudo.co.il/xss/level0.php",
		"http://sudo.co.il/xss/level1.php",
		"http://sudo.co.il/xss/level2.php",
		"http://sudo.co.il/xss/level3.php",
		"http://sudo.co.il/xss/level4.php",
		"http://www.sudo.co.il/xss/level5-1.php?p=your_payload",
		"http://sudo.co.il/xss/level5-2.php?p=test",
		"http://www.sudo.co.il/xss/level6.php?p=your_payload",
		"http://www.sudo.co.il/xss/level7.php?p=your_payload",
		"http://www.sudo.co.il/xss/level8.php?p=your_payload",
		"http://www.sudo.co.il/xss/level8-1.php?p=your_payload",
		"http://www.sudo.co.il/xss/level9.php?p=your_payload",
		"http://www.sudo.co.il/xss/level10.php?p=your_payload",

		//   not covered
		// 	"http://www.sudo.co.il/xss/level11.php?p=your_payload",
		// 	"http://sudo.co.il/xss/level12.php?p=",
		// 	"http://sudo.co.il/xss/level13.php?p=",
		// 	"http://www.sudo.co.il/xss/level14.php?js=analytics.js&p=76",
		// 	"http://www.sudo.co.il/xss/level15.php?se=39fc6ea9b5c7640b142e2352ec789820&p=658",
		// 	"http://www.sudo.co.il/xss/level16.php?ur=156&col=38",
		// 	"http://www.sudo.co.il/xss/level17.php?query=test&rt=qoyH3rafjJqbjA%3D%3D",
		// 	"http://www.sudo.co.il/xss/level18.php?tgi=J1MMFElcRxdDCggUUkZZUR1BFRIYV0IBQ1VCWkIZCENEEg%3D%3D&pr=d2b403270edb7f441a5289b1ceb8b97c&query=test",
		// 	"http://www.sudo.co.il/xss/level19.php?q=muhaha&tr=OzUnKVkoJEFBPEYxRTxCIUEoJlFJPScxTDkyIU07VylFK0JYTgpgCg%3D%3D",
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	now := time.Now()
	comps := make([]comp, 0)
	payloads := []string{
		"demo/payload-1.txt",
		"demo/payload-2.txt",
		"demo/payload-3.txt",
		"demo/payload-4.txt",
		"demo/payload-5.txt",
		"demo/payload-6.txt",
		"demo/payload-7.txt",
		"demo/payload-9.txt",
		"demo/payload-10.txt",
		"demo/payload-11.txt",
		"demo/payload-12.txt",
		"demo/payload-13.txt",
		"demo/payload-14.txt",
	}
	for _, p := range payloads {
		results, notfound, err := findXSS(logger, urls, p)
		if err != nil {
			fmt.Println(err)
			//os.Exit(1)
			continue
		}
		comp := comp{
			payload:  p,
			found:    len(results),
			total:    len(urls),
			notfound: notfound,
		}
		comps = append(comps, comp)
		if len(results) > 0 {
			fmt.Println(results)
		}
	}
	for _, c := range comps {
		fmt.Print("\n", c, "\n")
	}
	fmt.Print(time.Since(now))
}

func findXSS(log *zap.Logger, urls []string, payloadFile string) ([]rep, []string, error) {
	results := make([]rep, 0)
	notfount := make([]string, 0)
	for _, url := range urls {
		res, err := scanning.NewScan(log, model.Target{
			URL:    url,
			Method: "GET",
			Options: model.Options{
				CustomPayloadFile: payloadFile,
				OnlyCustomPayload: true,
			},
		})

		if err != nil {
			return nil, nil, err
		}

		if len(res.PoCs) == 0 {
			notfount = append(notfount, url)
			continue
		}
		result := rep{
			url: url,
			res: res,
		}

		results = append(results, result)
	}

	return results, notfount, nil
}

type rep struct {
	url string
	res model.Result
}

func (r rep) String() string {
	sep := "\n================================================\n"
	str := sep + r.url + "\n"
	for _, p := range r.res.PoCs {
		str += fmt.Sprintf("\n%v\n", p)
	}
	str += fmt.Sprintf("%s\n", r.res.Duration)
	return str
}

type comp struct {
	payload  string
	found    int
	total    int
	notfound []string
}

func (c comp) String() string {
	str := fmt.Sprintf("payload:%s \nfound %d of %d\n", c.payload, c.found, c.total)
	if len(c.notfound) > 0 {
		str += "not found urls:\n"
		for _, u := range c.notfound {
			str += u + "\n"
		}
	}
	return str
}
