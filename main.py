import pyshark
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import joblib
import matplotlib.pyplot as plt

scaler = joblib.load('scaler.pkl')
model = joblib.load('network_anomaly_model.pkl')

def process_packet(packet, anomaly_indices, anomaly_features):
    try:
        features = {
            'ifInOctets11': float(packet.frame_info.len) if 'frame_info' in packet else 0,
            'tcpInSegs': float(packet.tcp.segment_count) if 'tcp' in packet else 0,
            'icmpOutMsgs': float(packet.icmp.message_count) if 'icmp' in packet else 0
        }

        features_df = pd.DataFrame([features])
        features_scaled = scaler.transform(features_df)
        prediction = model.predict(features_scaled)

        if prediction == -1:
            anomaly_indices.append(packet.number)
            anomaly_features.append(features)  # Store features of the anomaly
    except AttributeError as e:
        print(f"Attribute error: {e}")
    except Exception as e:
        print(f"Error processing packet: {e}")

def capture_packets():
    capture = pyshark.LiveCapture(interface='Wi-Fi')

    anomaly_indices = []
    anomaly_features = []  # List to hold features of anomalies
    try:
        print("Starting live traffic capture. Press Ctrl+C to stop...")
        capture.sniff(timeout=60)  # Capture for a specified duration (e.g., 60 seconds)
        for packet in capture.sniff_continuously(packet_count=50):  # You can adjust packet_count
            process_packet(packet, anomaly_indices, anomaly_features)
    except KeyboardInterrupt:
        print("\nLive capture stopped by user.")
    except EOFError:
        print("Stream ended unexpectedly.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if anomaly_indices:
            print(f"Total anomalies detected: {len(anomaly_indices)}")
            print(f"Indices of anomalies: {anomaly_indices}")

            # Tabular representation of detected anomalies
            anomalies_df = pd.DataFrame(anomaly_features)
            print("Anomalies detected (features):")
            print(anomalies_df)

            # Graphical representation for detected anomalies
            anomalies_df.plot(kind='bar', title='Anomalies Detected Features', figsize=(10, 5))
            plt.xlabel('Anomaly Index')
            plt.ylabel('Feature Values')
            plt.legend(title='Features')
            plt.tight_layout()  # Adjust layout to make room for labels
            plt.show()  # Display the plot

            print("Anomalies detected. Investigate the causes and consider mitigating actions.")
        else:
            # Create a DataFrame with 0 values for the features
            anomalies_df = pd.DataFrame({
                'ifInOctets11': [0],
                'tcpInSegs': [0],
                'icmpOutMsgs': [0]
            })
            print("No anomalies detected. System is operating normally.")
            print(anomalies_df)

            # Graphical representation for no anomalies
            anomalies_df.plot(kind='bar', title='No Anomalies Detected', figsize=(10, 5))
            plt.xlabel('Anomaly Index')
            plt.ylabel('Feature Values')
            plt.xticks(ticks=[0], labels=['No Anomalies'])  # Label the single bar
            plt.tight_layout()  # Adjust layout to make room for labels
            plt.show()  # Display the plot

if __name__ == "__main__":
    capture_packets()
