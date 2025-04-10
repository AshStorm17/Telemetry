#!/bin/bash
set -e

# Function to clean up background processes on exit
cleanup() {
    echo "Terminating background processes..."
    # Terminate the telemetry and packet sending processes
    kill "$TELEMETRY_PID" "$SEND_PID" 2>/dev/null
    sudo pkill -f tcpdump 2>/dev/null
    # Wait for the background processes to exit
    wait "$TELEMETRY_PID" "$SEND_PID" 2>/dev/null
    echo "Cleanup complete."
}

# Trap keyboard interrupt (Ctrl+C) and termination signals
trap cleanup SIGINT SIGTERM

# Start the telemetry capture process in the background
echo "Starting telemetry capture..."
sudo python3 main_telemetry.py &
TELEMETRY_PID=$!

sleep 15

echo "Starting packet sending..."
sudo python3 CC2DC.py &
SEND_PID=$!

wait "$TELEMETRY_PID" "$SEND_PID"
