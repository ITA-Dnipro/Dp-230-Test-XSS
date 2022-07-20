package server

import (
	"context"
	"log"

	"go.uber.org/zap"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/client"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/kafka"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/scanning"
)

type Server struct {
	logger       *zap.Logger
	consumer     *kafka.Consumer
	scanner      *scanning.Scanner
	reportClient *client.ReportClient
}

func NewServer(logger *zap.Logger, consumer *kafka.Consumer, scanner *scanning.Scanner, reportClient *client.ReportClient) *Server {
	return &Server{
		logger:       logger,
		consumer:     consumer,
		scanner:      scanner,
		reportClient: reportClient,
	}
}

func (s *Server) Start() {
	ctx := context.Background()
	for {
		message, err := s.consumer.FetchMessage(ctx)
		if err != nil {
			log.Printf("fetch: %v\n", err)
		}
		tr := model.TestResult{Type: "xss"}
		for _, url := range message.Value.URLs {
			res, err := s.scanner.Scan(url)
			if err != nil {
				log.Printf("scan:%v\n", err)
			}
			tr.Results = append(tr.Results, res)
		}
		if err = s.reportClient.PushResult(ctx, message.Value.ID, tr); err != nil {
			log.Printf(" error:%v\n", err)
		}
	}
}
