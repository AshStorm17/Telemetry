from scapy.all import rdpcap, Raw
from datetime import datetime
import argparse
import csv

last_seen = {}

def send_sos_packet(cc_name, mac, last_received):
    msg = "SOS PACKET STARTED\n"
    msg += f"MAC: {mac}\n"
    msg += f"Last Received: {datetime.strftime(last_received,'%Y-%m-%dT%H:%M:%S.%f')}\n"
    msg += "SOS PACKET ENDED\n"
    with open(f"{cc_name}_tcp_payload.txt", "a") as f:
        f.writelines(msg)

def update_last_seen(cc_name):
    filename = f"{cc_name}_SOS.csv"
    rows = []

    try:
        with open(filename, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                rows.append(row)
    except FileNotFoundError:
        print(f"File '{filename}' not found.")
        return

    current_time = datetime.now()
    threshold_seconds = 10

    for row in rows:
        mac = row["MAC"]
        if mac in last_seen:
            row["last_seen"] = last_seen[mac].strftime("%Y-%m-%dT%H:%M:%S.%f")
        elif "last_seen" in row and row["last_seen"]:
            try:
                row_timestamp = datetime.strptime(row["last_seen"], "%Y-%m-%dT%H:%M:%S.%f")
                if (current_time - row_timestamp).total_seconds() > threshold_seconds:
                    send_sos_packet(cc_name, mac, row_timestamp)
            except ValueError:
                print(f"Timestamp format error in CSV for MAC '{mac}': {row['last_seen']}")
        elif "last_seen" not in row or not row["last_seen"]:
            print(f"No last seen timestamp for MAC '{mac}'.")

    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ["MAC", "last_seen"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def find_start_end_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and prints the entire packet if it contains "PACKET STARTED" or "PACKET ENDED".

    Args:
        pcap_file (str): The path to the pcap file.
    """
    try:
        packets = rdpcap(pcap_file)

        for packet_number, packet in enumerate(packets):
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "PACKET STARTED" in payload or "PACKET ENDED" in payload:

                    payload_lines = payload.split("\n")
                    # for i, line in enumerate(payload_lines):
                    #     print(f"{i+1}: {line}")

                    mac_line = payload_lines[2]
                    mac = mac_line.split(": ")[1]
                    print(f"MAC: {mac}")

                    timestamp_line = payload_lines[4]
                    timestamp_str = timestamp_line.split(": ")[1]
                    try:
                        # Try parsing with milliseconds
                        dt_part, ms_part = timestamp_str.split('.')
                        dt_object = datetime.strptime(dt_part, "%Y-%m-%d %H:%M:%S")
                        microseconds = int(ms_part) * 1000  # Convert milliseconds to microseconds
                        timestamp = dt_object.replace(microsecond=microseconds)
                        last_seen[mac] = timestamp
                        print(f"Timestamp: {timestamp}")
                    except ValueError:
                        print(f"Error parsing timestamp: {timestamp_str}")

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    # Parse the command line arguments
    parser = argparse.ArgumentParser(description="Checks last seen timestamps switches/routers")
    parser.add_argument("pcap_file", type=str, help="The path to the pcap file.")
    parser.add_argument("CC_Name", type=str, help="The name of the Control Center.")
    args = parser.parse_args()

    pcap_file_path = args.pcap_file
    CC_Name = args.CC_Name

    find_start_end_packets_scapy(pcap_file_path)
    update_last_seen(CC_Name)