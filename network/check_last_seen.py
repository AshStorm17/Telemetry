from scapy.all import rdpcap, Raw
import datetime
import argparse
import csv

last_seen = {}

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
                    for i, line in enumerate(payload_lines):
                        print(f"{i+1}: {line}")

                    mac_line = payload_lines[2]
                    mac = mac_line.split(": ")[1]
                    print(f"MAC: {mac}")

                    timestamp_line = payload_lines[4]
                    timestamp = timestamp_line.split(": ")[1]
                    last_seen[mac] = timestamp
                    print(f"Timestamp: {timestamp}")

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def send_sos_packet(self, mac, last_received):
    msg = "SOS PACKET STARTED\n"
    msg += f"MAC: {mac}\n"
    msg += f"Last Received: {last_received.strftime('%Y-%m-%dT%H:%M:%S.%f')}\n"
    msg += "SOS PACKET ENDED\n"
    with open({CC_Name}+"_tcp_payload.txt", "a") as f:
        f.writelines(msg)

def update_last_seen(CC_Name):
    filename = f"{CC_Name}_SOS.csv"
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
            updated_time = last_seen[mac]
            row["last_seen"] = updated_time.strftime("%Y-%m-%dT%H:%M:%S.%f")
        
        try:
            row_timestamp = datetime.strptime(row["last_seen"], "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            print(f"Timestamp format error for MAC '{mac}': {row['last_seen']}")
            continue

        if (current_time-row_timestamp).total_seconds() > threshold_seconds:
            send_sos_packet(CC_Name, mac, row["last_seen"])

    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ["MAC", "last_seen"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

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
