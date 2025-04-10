import joblib
import os
import numpy as np

MODEL_PATH = os.path.join('Models', 'model.pkl')

# Load model once
model = joblib.load(MODEL_PATH)

def infer_health_metrics(parsed_data):
    # Extract features from parsed_data
    timestamps = [pkt['timestamp'] for pkt in parsed_data]
    sizes = [pkt['size'] for pkt in parsed_data]

    # Example: Predict a "health score" for each packet
    X = np.array(sizes).reshape(-1, 1)
    scores = model.predict(X)

    return {
        "timestamps": timestamps,
        "scores": scores.tolist()
    }
