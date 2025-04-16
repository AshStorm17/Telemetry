import csv
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import session
from app import app
from models import db
from models.telemetry import TelemetryData

def parse_csv(filename):
    swstats_dicts = []

    with open(filename, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or len(row) < 3:
                continue
            
            CC_Name = row[0]
            num_macs = int(row[1])
            timenow = row[2]

            index = 3
            swstats = {}

            for _ in range(num_macs):
                mac = row[index]
                stats = {}
                stats['Number of Ports'] = row[index + 1]
                stats['Latest Timestamp'] = f"{row[index + 2]} {row[index + 3]}"
                stats['Oldest Timestamp'] = f"{row[index + 4]} {row[index + 5]}"
                keys = [
                    'Total Packets', 'Total Bytes', 'Total Errors',
                    'Total Rx Packets', 'Total Rx Bytes', 'Total Rx Errors',
                    'Total Tx Packets', 'Total Tx Bytes', 'Total Tx Errors',
                    'Min Rx Packets', 'Max Rx Packets', 'Min Rx Bytes', 'Max Rx Bytes',
                    'Min Rx Errors', 'Max Rx Errors', 'Min Tx Packets', 'Max Tx Packets',
                    'Min Tx Bytes', 'Max Tx Bytes', 'Min Tx Errors', 'Max Tx Errors',
                    'Min Rx Utilization', 'Max Rx Utilization', 'Min Tx Utilization', 'Max Tx Utilization',
                    'Min Throughput (Mbps)', 'Max Throughput (Mbps)', 'Min Buffer Occupancy', 'Max Buffer Occupancy',
                    'Average Rx Packets', 'Average Rx Bytes', 'Average Rx Errors',
                    'Average Tx Packets', 'Average Tx Bytes', 'Average Tx Errors',
                    'Average Rx Utilization', 'Average Tx Utilization',
                    'Average Throughput (Mbps)', 'Average Buffer Occupancy'
                ]
                for i, key in enumerate(keys):
                    stats[key] = row[index + 6 + i]

                # Store each stat in the database
                for parameter_name, value in stats.items():
                    telemetry_entry = TelemetryData(
                        timestamp=timenow,
                        mac=mac,
                        parameter_name=parameter_name,
                        value=float(value) if value.replace('.', '', 1).isdigit() else 0.0
                    )
                    db.session.add(telemetry_entry)
                
                swstats[mac] = stats
                index += 6 + len(keys) + 4

            swstats_dicts.append({
                'CC_Name': CC_Name,
                'Timestamp': timenow,
                'Stats': swstats
            })

    return swstats_dicts

def parse_cc2dc_packet(parsed_dict):
    tcppayload = "CC2DC PACKET STARTED\n"
    tcppayload += f"{parsed_dict['CC_Name']}\n"
    tcppayload += f"{len(parsed_dict['Stats'])}\n"
    tcppayload += f"{parsed_dict['Timestamp']}\n"

    swstats = parsed_dict['Stats']
    for mac, stats in swstats.items():
        tcppayload += f"{mac}\n"
        for value in stats.values():
            tcppayload += f"{value}\n"

    checksum = sum(ord(c) for c in tcppayload) % 65536
    tcppayload += f"Checksum: {checksum}\n"
    tcppayload += "CC2DC PACKET ENDED"
    return tcppayload

def main():
    filename = '../network/dc_data.csv'
    try:
        all_packets = parse_csv(filename)
        print(all_packets[3])
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    with app.app_context():
        main()
