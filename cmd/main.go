package main

import (
	"log"

	"go.uber.org/zap"
	"google.golang.org/grpc"

	"github.com/kelseyhightower/envconfig"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/client"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/config"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/kafka"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/scanning"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/server"
)

func main() {
	var cfg config.Config
	if err := envconfig.Process("xss", &cfg); err != nil {
		log.Fatal(err.Error())
	}

	logger, _ := zap.NewProduction()
	conn, err := grpc.Dial(":9090", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %s", err)
	}
	scanner := scanning.NewScanner(logger)
	consumer := kafka.New(cfg)
	reportClient := client.NewReportClient(conn)
	defer conn.Close()
	srv := server.NewServer(logger, consumer, scanner, reportClient)
	srv.Start()
}
