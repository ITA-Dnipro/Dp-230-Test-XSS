package config

// Config takes config parameters from environment, or uses default.
type Config struct {
	Kafka *KafkaConfig
}

// KafkaConfig include parameters for Kafka.
type KafkaConfig struct {
	Brokers []string `default:"localhost:9091"`
	GroupID string   `default:"xss"`
	Topic   string   `default:"xss-check"`
}
