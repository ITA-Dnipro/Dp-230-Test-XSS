package kafka

import (
	"context"
	"encoding/json"
	"log"
	"os"

	kafkago "github.com/segmentio/kafka-go"

	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/config"
	"github.com/ITA-Dnipro/Dp-230-Test-XSS/internal/model"
)

// Consumer has kafka reader itself.
type Consumer struct {
	Reader *kafkago.Reader
}

// New returns new Kafka consumer.
func New(conf config.Config) *Consumer {
	//TODO: replace with zap
	l := log.New(os.Stdout, "kafka reader: ", 0)
	r := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:     conf.Kafka.Brokers,
		Topic:       conf.Kafka.Topic,
		GroupID:     conf.Kafka.GroupID,
		StartOffset: kafkago.FirstOffset,
		Logger:      l,
		MaxAttempts: 5,
	})

	c := &Consumer{Reader: r}

	return c
}

// FetchMessage reads messages from Kafka wrapping them into strut.
func (c *Consumer) FetchMessage(ctx context.Context) (model.Message, error) {
	message := model.Message{}

	msg, err := c.Reader.ReadMessage(ctx)
	if err != nil {
		return message, err
	}

	task := model.Task{}
	err = json.Unmarshal(msg.Value, &task)
	if err != nil {
		return message, err
	}
	message.Key = string(msg.Key)
	message.Value = task
	message.Time = msg.Time

	return message, nil
}
