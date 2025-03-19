#!/usr/bin/python
import socket

# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific port
port = 12345
sock.bind(('', port))

while True:
    # Receive data from the socket
    data, addr = sock.recvfrom(1024)
    print("Received:", data.decode())
