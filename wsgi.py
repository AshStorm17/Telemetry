# wsgi.py
from app import app, socketio
import time
import threading
from utils.plot_graphs import generate_graph
import os

# Define a background thread for live graph generation
def live_graph_updater(interval=5):  # update every 5 seconds
    csv_path = os.path.join(os.path.dirname(__file__), "network/dc_data.csv")
    while True:
        try:
            graph_paths = generate_graph(csv_path)
            socketio.emit("graphs_updated", graph_paths)
        except Exception as e:
            print(f"[Live Graph] Error generating graphs: {e}")
        time.sleep(interval)

# Start live graph generation thread
graph_thread = threading.Thread(target=live_graph_updater, daemon=True)
graph_thread.start()

# Run with SocketIO
if __name__ == "__main__":
    socketio.run(app, host="127.0.0.1", port=5000, debug=True)
