package main

import (
	"log"
	"os"
	"os/signal"
	"time"

	"github.com/IBM/sarama"
)

func main() {
	// Kafka broker addresses
	brokers := []string{"localhost:9092"}

	// Kafka topic to produce to
	topic := "network-telemetry"

	// Create a new Kafka producer configuration
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true

	// Create a new Kafka producer
	producer, err := sarama.NewSyncProducer(brokers, config)
	if err != nil {
		log.Fatalf("Error creating producer: %v", err)
	}
	defer producer.Close()

	// Handle interrupts to gracefully shut down the producer
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	// Simulate sending network telemetry data
	for {
		select {
		case <-signals:
			log.Println("Interrupt received, shutting down...")
			return
		default:
			// Simulate network telemetry data
			telemetryData := `{"timestamp": "` + time.Now().Format(time.RFC3339) + `", "bytes_sent": 1024, "bytes_received": 2048}`

			// Create a Kafka message
			message := &sarama.ProducerMessage{
				Topic: topic,
				Value: sarama.StringEncoder(telemetryData),
			}

			// Send the message to Kafka
			partition, offset, err := producer.SendMessage(message)
			if err != nil {
				log.Printf("Failed to send message: %v\n", err)
			} else {
				log.Printf("Message sent to partition %d at offset %d\n", partition, offset)
			}

			// Wait for a second before sending the next message
			time.Sleep(1 * time.Second)
		}
	}
}