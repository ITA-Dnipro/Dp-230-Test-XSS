package main

import (
	"flag"
	"fmt"
	"os"

	"go.uber.org/zap"

	"test/internal/model"
	"test/internal/scanning"
)

var (
	url     = flag.String("u", "https://xss-game.appspot.com/level1/frame", "URL")
	payload = flag.String("p", "./payload.txt", "Use custom payloads list file")
)

func main() {
	flag.Parse()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	opt := model.Options{
		CustomPayloadFile: *payload,
		OnlyCustomPayload: true,
	}
	result, err := scanning.NewScan(logger, model.Target{
		URL:     *url,
		Method:  "GET",
		Options: opt,
	})

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("%+v\n", result)
}
