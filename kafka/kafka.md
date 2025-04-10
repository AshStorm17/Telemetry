# Setting Up Apache Kafka on WSL
### Install Java
Kafka requires Java, so install it using:
```
sudo apt update
sudo apt install openjdk-11-jdk -y
```

Verify the installation:
```
java -version
```

### Download & Install Kafka
Navigate to /usr/local and download Kafka:
```
cd /usr/local
sudo wget https://downloads.apache.org/kafka/3.5.1/kafka_2.13-3.5.1.tgz
```

Extract and rename:
```
sudo tar -xvzf kafka_2.13-3.5.1.tgz
sudo mv kafka_2.13-3.5.1 kafka
```

### Add Kafka to PATH
Edit your shell config (~/.bashrc or ~/.zshrc):
```
echo 'export PATH=$PATH:/usr/local/kafka/bin' >> ~/.bashrc
source ~/.bashrc
```

Verify:
```
kafka-topics.sh --version
```

### Start Zookeeper
Kafka needs Zookeeper to manage brokers. Start it using:
```
zookeeper-server-start.sh /usr/local/kafka/config/zookeeper.properties
```

OR add an alias:
```
echo 'alias start-zk="zookeeper-server-start.sh /usr/local/kafka/config/zookeeper.properties"' >> ~/.bashrc
source ~/.bashrc
```

Start using:
```
start-zk
```

### Start Kafka
Run Kafka with the default port (9092):
```
kafka-server-start.sh /usr/local/kafka/config/server.properties
```

Or create an alias to run with a custom port:
```
echo 'start-kafka() { kafka-server-start.sh /usr/local/kafka/config/server.properties --override listeners=PLAINTEXT://localhost:$1; }' >> ~/.bashrc
source ~/.bashrc
```

Now, start Kafka with:
```
start-kafka 9092
```

### Verify Kafka is Running
Check Java processes:
```
jps
```

Expected output:
```
12345 QuorumPeerMain   # (Zookeeper)
67890 Kafka            # (Kafka)
```
