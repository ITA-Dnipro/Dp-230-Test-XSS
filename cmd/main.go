package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/scanning"
	"go.uber.org/zap"
)

var (
	url = flag.String("u", "https://xss-game.appspot.com/level1/frame", "URL")
)

func main() {
	flag.Parse()

	logger, _ := zap.NewProduction()

	opt := model.Options{
		// CustomPayloadFile: *payload,
		// OnlyCustomPayload: true,
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

	fmt.Printf("%+v\n", len(result.PoCs))
}
