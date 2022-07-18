package main

import (
	"flag"
	"log"

	"go.uber.org/zap"

	"github.com/kelseyhightower/envconfig"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/config"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/kafka"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/scanning"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/server"
)

func main() {
	flag.Parse()

	var cfg config.Config
	if err := envconfig.Process("xss", &cfg); err != nil {
		log.Fatal(err.Error())
	}

	logger, _ := zap.NewProduction()

	scanner := scanning.NewScanner(logger)
	consumer := kafka.New(cfg)
	srv := server.NewServer(logger, consumer, scanner)
	srv.Start()
}
