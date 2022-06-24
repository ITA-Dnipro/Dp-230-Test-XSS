package main

import (
	"flag"
	"fmt"
	"os"

	dalfox "github.com/hahwul/dalfox/v2/lib"
)

var (
	url     = flag.String("u", "https://xss-game.appspot.com/level1/frame", "URL")
	payload = flag.String("p", "./payload.txt", "Use custom payloads list file")
)

func main() {
	flag.Parse()

	opt := dalfox.Options{
		CustomPayloadFile: *payload,
		OnlyCustomPayload: true,
		FindingDOM:        true,
	}
	result, err := dalfox.NewScan(dalfox.Target{
		URL:     *url,
		Method:  "GET",
		Options: opt,
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(result)
}
