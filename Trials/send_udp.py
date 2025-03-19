#!/usr/bin/python
import socket
import sys
import time

# Get the IP address of h3 from the command line argument
host_ip = sys.argv[1]

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Define the port
port = 12345

while True:
    # Send the message "Hello" to h3
    sock.sendto(b'Hello', (host_ip, port))
    print("Sent 'Hello' to h3")
    time.sleep(3)
