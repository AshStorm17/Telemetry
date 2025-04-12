from scapy.all import rdpcap, Raw
import datetime
import argparse

def find_start_end_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and prints the entire packet if it contains "PACKET STARTED" or "PACKET ENDED".

    Args:
        pcap_file (str): The path to the pcap file.
    """
    switch_wise_statistics = {} 
    try:
        packets = rdpcap(pcap_file)

        for packet_number, packet in enumerate(packets):
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore') # Decode, ignoring errors
                if "PACKET STARTED" in payload or "PACKET ENDED" in payload:
                    payload_lines = payload.split("\n")
                    mac_line = payload_lines[2]
                    mac = mac_line.split(": ")[1]
                    num_ports_line = payload_lines[3]
                    num_ports = int(num_ports_line.split(": ")[1])
                    timestamp_line = payload_lines[4]
                    timestamp = timestamp_line.split(": ")[1]
                    port_stats = []
                    for i in range(5, 5 + num_ports):
                        port_line = payload_lines[i]
                        port_stats.append(port_line)
                    port_wise_statistics = {}
                    for port_stat in port_stats:
                        port_stat_parts = port_stat.split(", ")
                        port_id = port_stat_parts[0].split(" ")[1]
                        rxpkts = int(port_stat_parts[0].split("=")[1])
                        rxbytes = int(port_stat_parts[1].split("=")[1])
                        rxerrs = int(port_stat_parts[2].split("=")[1])
                        txpkts = int(port_stat_parts[3].split("=")[1])
                        txbytes = int(port_stat_parts[4].split("=")[1])
                        txerrs = int(port_stat_parts[5].split("=")[1])
                        port_wise_statistics[port_id] = {
                            'Rx Packets': rxpkts,
                            'Rx Bytes': rxbytes,
                            'Rx Errors': rxerrs,
                            'Tx Packets': txpkts,
                            'Tx Bytes': txbytes,
                            'Tx Errors': txerrs
                        }

                    if mac not in switch_wise_statistics:
                        switch_wise_statistics[mac] = {
                            'Number of Ports': num_ports,
                            'Latest Timestamp': datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"),
                            'Oldest Timestamp': datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"),
                            'Total Packets': 0,
                            'Total Bytes': 0,
                            'Total Errors': 0,
                            'Total Rx Packets': 0,
                            'Total Rx Bytes': 0,
                            'Total Rx Errors': 0,
                            'Total Tx Packets': 0,
                            'Total Tx Bytes': 0,
                            'Total Tx Errors': 0,
                            'Min Rx Packets': float('inf'),
                            'Max Rx Packets': float('-inf'),
                            'Min Rx Bytes': float('inf'),
                            'Max Rx Bytes': float('-inf'),
                            'Min Rx Errors': float('inf'),
                            'Max Rx Errors': float('-inf'),
                            'Min Tx Packets': float('inf'),
                            'Max Tx Packets': float('-inf'),
                            'Min Tx Bytes': float('inf'),
                            'Max Tx Bytes': float('-inf'),
                            'Min Tx Errors': float('inf'),
                            'Max Tx Errors': float('-inf'),
                            'Average Rx Packets': 0,
                            'Average Rx Bytes': 0,
                            'Average Rx Errors': 0,
                            'Average Tx Packets': 0,
                            'Average Tx Bytes': 0,
                            'Average Tx Errors': 0
                        }
                    
                    switch_wise_statistics[mac]['Latest Timestamp'] = max(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), switch_wise_statistics[mac]['Latest Timestamp'])
                    switch_wise_statistics[mac]['Oldest Timestamp'] = min(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), switch_wise_statistics[mac]['Oldest Timestamp'])

                    for port_id, port_stat in port_wise_statistics.items():
                        switch_wise_statistics[mac]['Total Packets'] += port_stat['Rx Packets'] + port_stat['Tx Packets']
                        switch_wise_statistics[mac]['Total Bytes'] += port_stat['Rx Bytes'] + port_stat['Tx Bytes']
                        switch_wise_statistics[mac]['Total Errors'] += port_stat['Rx Errors'] + port_stat['Tx Errors']
                        switch_wise_statistics[mac]['Total Rx Packets'] += port_stat['Rx Packets']
                        switch_wise_statistics[mac]['Total Rx Bytes'] += port_stat['Rx Bytes']
                        switch_wise_statistics[mac]['Total Rx Errors'] += port_stat['Rx Errors']
                        switch_wise_statistics[mac]['Total Tx Packets'] += port_stat['Tx Packets']
                        switch_wise_statistics[mac]['Total Tx Bytes'] += port_stat['Tx Bytes']
                        switch_wise_statistics[mac]['Total Tx Errors'] += port_stat['Tx Errors']

                        switch_wise_statistics[mac]['Min Rx Packets'] = min(switch_wise_statistics[mac]['Min Rx Packets'], port_stat['Rx Packets'])
                        switch_wise_statistics[mac]['Max Rx Packets'] = max(switch_wise_statistics[mac]['Max Rx Packets'], port_stat['Rx Packets'])
                        switch_wise_statistics[mac]['Min Rx Bytes'] = min(switch_wise_statistics[mac]['Min Rx Bytes'], port_stat['Rx Bytes'])
                        switch_wise_statistics[mac]['Max Rx Bytes'] = max(switch_wise_statistics[mac]['Max Rx Bytes'], port_stat['Rx Bytes'])
                        switch_wise_statistics[mac]['Min Rx Errors'] = min(switch_wise_statistics[mac]['Min Rx Errors'], port_stat['Rx Errors'])
                        switch_wise_statistics[mac]['Max Rx Errors'] = max(switch_wise_statistics[mac]['Max Rx Errors'], port_stat['Rx Errors'])
                        switch_wise_statistics[mac]['Min Tx Packets'] = min(switch_wise_statistics[mac]['Min Tx Packets'], port_stat['Tx Packets'])
                        switch_wise_statistics[mac]['Max Tx Packets'] = max(switch_wise_statistics[mac]['Max Tx Packets'], port_stat['Tx Packets'])
                        switch_wise_statistics[mac]['Min Tx Bytes'] = min(switch_wise_statistics[mac]['Min Tx Bytes'], port_stat['Tx Bytes'])
                        switch_wise_statistics[mac]['Max Tx Bytes'] = max(switch_wise_statistics[mac]['Max Tx Bytes'], port_stat['Tx Bytes'])
                        switch_wise_statistics[mac]['Min Tx Errors'] = min(switch_wise_statistics[mac]['Min Tx Errors'], port_stat['Tx Errors'])
                        switch_wise_statistics[mac]['Max Tx Errors'] = max(switch_wise_statistics[mac]['Max Tx Errors'], port_stat['Tx Errors'])

                    switch_wise_statistics[mac]['Average Rx Packets'] = switch_wise_statistics[mac]['Total Rx Packets'] / num_ports
                    switch_wise_statistics[mac]['Average Rx Bytes'] = switch_wise_statistics[mac]['Total Rx Bytes'] / num_ports
                    switch_wise_statistics[mac]['Average Rx Errors'] = switch_wise_statistics[mac]['Total Rx Errors'] / num_ports
                    switch_wise_statistics[mac]['Average Tx Packets'] = switch_wise_statistics[mac]['Total Tx Packets'] / num_ports
                    switch_wise_statistics[mac]['Average Tx Bytes'] = switch_wise_statistics[mac]['Total Tx Bytes'] / num_ports
                    switch_wise_statistics[mac]['Average Tx Errors'] = switch_wise_statistics[mac]['Total Tx Errors'] / num_ports


    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    return switch_wise_statistics


def craft_to_cc2dc_protocol_payload(swstats, CC_Name):
    """
    Craft the packets to send to the Data Center using the CC2DC protocol."
    """
    timenow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    tcppayload = "CC2DC PACKET STARTED\n"
    tcppayload += f"{CC_Name}\n"
    tcppayload += f"{len(swstats)}\n"
    tcppayload += f"{timenow}\n"
    for mac, stats in swstats.items():
        tcppayload += f"{mac}\n"
        tcppayload += f"{stats['Number of Ports']}\n"
        tcppayload += f"{stats['Latest Timestamp']}\n"
        tcppayload += f"{stats['Oldest Timestamp']}\n"
        tcppayload += f"{stats['Total Packets']}\n"
        tcppayload += f"{stats['Total Bytes']}\n"
        tcppayload += f"{stats['Total Errors']}\n"
        tcppayload += f"{stats['Total Rx Packets']}\n"
        tcppayload += f"{stats['Total Rx Bytes']}\n"
        tcppayload += f"{stats['Total Rx Errors']}\n"
        tcppayload += f"{stats['Total Tx Packets']}\n"
        tcppayload += f"{stats['Total Tx Bytes']}\n"
        tcppayload += f"{stats['Total Tx Errors']}\n"
        tcppayload += f"{stats['Min Rx Packets']}\n"
        tcppayload += f"{stats['Max Rx Packets']}\n"
        tcppayload += f"{stats['Min Rx Bytes']}\n"
        tcppayload += f"{stats['Max Rx Bytes']}\n"
        tcppayload += f"{stats['Min Rx Errors']}\n"
        tcppayload += f"{stats['Max Rx Errors']}\n"
        tcppayload += f"{stats['Min Tx Packets']}\n"
        tcppayload += f"{stats['Max Tx Packets']}\n"
        tcppayload += f"{stats['Min Tx Bytes']}\n"
        tcppayload += f"{stats['Max Tx Bytes']}\n"
        tcppayload += f"{stats['Min Tx Errors']}\n"
        tcppayload += f"{stats['Max Tx Errors']}\n"
        tcppayload += f"{stats['Average Rx Packets']}\n"
        tcppayload += f"{stats['Average Rx Bytes']}\n"
        tcppayload += f"{stats['Average Rx Errors']}\n"
        tcppayload += f"{stats['Average Tx Packets']}\n"
        tcppayload += f"{stats['Average Tx Bytes']}\n"
        tcppayload += f"{stats['Average Tx Errors']}\n"
    tcppayload += "CC2DC PACKET ENDED"


    return tcppayload

def end2end_cc2dc(pcap_file_path, CC_Name):
    swstats = find_start_end_packets_scapy(pcap_file_path)
    print(swstats)

    # Craft the TCP payload
    tcp_payload = craft_to_cc2dc_protocol_payload(swstats, CC_Name)
    # Save to a file cc1_payload.txt
    with open(f"{CC_Name.lower()}_payload.txt", "w") as f:
        f.write(tcp_payload)

    print(f"Payload saved to {CC_Name.lower()}_payload.txt")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract switch statistics from a pcap file.")
    parser.add_argument("pcap_file", type=str, help="The path to the pcap file.")
    parser.add_argument("CC_Name", type=str, help="The name of the Control Center.")
    args = parser.parse_args()

    pcap_file_path = args.pcap_file
    CC_Name = args.CC_Name

    swstats = find_start_end_packets_scapy(pcap_file_path)
    print(swstats)

    tcp_payload = craft_to_cc2dc_protocol_payload(swstats, CC_Name)
    with open(f"{CC_Name.lower()}_payload.txt", "w") as f:
        f.write(tcp_payload)

    print(f"Payload saved to {CC_Name.lower()}_payload.txt")


