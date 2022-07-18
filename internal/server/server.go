package server

import (
	"context"
	"log"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/kafka"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/scanning"
	"go.uber.org/zap"
)

type Server struct {
	logger   *zap.Logger
	consumer *kafka.Consumer
	scanner  *scanning.Scanner
}

func NewServer(logger *zap.Logger, consumer *kafka.Consumer, scanner *scanning.Scanner) *Server {
	return &Server{
		logger:   logger,
		consumer: consumer,
		scanner:  scanner,
	}
}

func (s *Server) Start() {
	ctx := context.Background()
	for {
		message, err := s.consumer.FetchMessage(ctx)
		if err != nil {
			log.Printf("Error fetching message: %v\n", err)
		}
		results := model.Results{ID: message.Value.ID}
		for _, url := range message.Value.URLs {
			res, err := s.scanner.Scan(url)
			if err != nil {
				log.Printf("Error-based check error:%v\n", err)
			}
			results.Results = append(results.Results, res)
		}
		log.Println(results)
		// set it to nil for stop processing previous result while no messages from Kafka.
	}
}
