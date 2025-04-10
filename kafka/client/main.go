package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/IBM/sarama"
)

func main() {
	// Kafka broker addresses
	brokers := []string{"localhost:9092"}

	// Kafka topic to consume from
	topic := "network-telemetry"

	// Create a new Kafka consumer configuration
	config := sarama.NewConfig()
	config.Consumer.Return.Errors = true

	// Create a new Kafka consumer
	consumer, err := sarama.NewConsumer(brokers, config)
	if err != nil {
		log.Fatalf("Error creating consumer: %v", err)
	}
	defer consumer.Close()

	// Create a partition consumer for the topic
	partitionConsumer, err := consumer.ConsumePartition(topic, 0, sarama.OffsetNewest)
	if err != nil {
		log.Fatalf("Error creating partition consumer: %v", err)
	}
	defer partitionConsumer.Close()

	// Handle interrupts to gracefully shut down the consumer
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)

	// Process messages from the Kafka topic
	for {
		select {
		case msg := <-partitionConsumer.Messages():
			log.Printf("Received message: %s\n", string(msg.Value))
		case err := <-partitionConsumer.Errors():
			log.Printf("Error: %v\n", err)
		case <-signals:
			log.Println("Interrupt received, shutting down...")
			return
		}
	}
}
