from scapy.all import rdpcap, Raw
import datetime
import argparse

def find_switch_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and prints the entire packet if it contains "PACKET STARTED" or "PACKET ENDED".

    Args:
        pcap_file (str): The path to the pcap file.
    """
    switch_wise_statistics = {} # This is a dictionary of dictionaries. The outer dictionary is indexed by the MAC address of the switch. The inner dictionary is indexed by the following fieds
    # 'Number of Ports', 'Latest Timestamp', 'Oldest Timestamp', 'Total Packets', 'Total Bytes', 'Total Errors', 'Total Rx Packets', 'Total Rx Bytes', 'Total Rx Errors', 'Total Tx Packets', 'Total Tx Bytes', 'Total Tx Errors'
    # 'Min Rx Packets', 'Max Rx Packets', 'Min Rx Bytes', 'Max Rx Bytes', 'Min Rx Errors', 'Max Rx Errors', 'Min Tx Packets', 'Max Tx Packets', 'Min Tx Bytes', 'Max Tx Bytes', 'Min Tx Errors', 'Max Tx Errors'
    # 'Average Rx Packets', 'Average Rx Bytes', 'Average Rx Errors', 'Average Tx Packets', 'Average Tx Bytes', 'Average Tx Errors'
    # This is added to the dictionary if the packet contains "PACKET STARTED" or "PACKET ENDED" and has Is Switch: True. We will update this dictionary as we go through the packets.

    try:
        packets = rdpcap(pcap_file)

        for packet_number, packet in enumerate(packets):
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                if "PACKET STARTED" in payload or "PACKET ENDED" in payload:
                    # Append time to the file
                    # with open("Hello1.txt", "a") as f:
                    #     f.write(str(datetime.datetime.now()))
                    # print(f"Packet Number: {packet_number + 1}") # Scapy packets are 0-indexed.
                    # Show only the load
                    # print(payload)
                    # Split the payload according to this:
                    # Packet Number: 22
                    # 55PACKET STARTED
                    # Is Switch: True
                    # MAC: 72:1d:b6:88:ef:41
                    # Number of Ports: 4
                    # Timestamp: 2025-03-22 06:27:13.182
                    # Port 4: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 1: Rxpkts=0, Rxbytes=77, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 2: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 3: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=77, Txerrs=0
                    # PACKET ENDED

                    # Split the payload into lines
                    payload_lines = payload.split("\n")
                    #Print line numbers
                    for i, line in enumerate(payload_lines):
                        print(f"{i+1}: {line}")

                    if payload_lines[1].split(": ")[1] == "True":

                        # Extract the MAC address
                        mac_line = payload_lines[2]
                        mac = mac_line.split(": ")[1]
                        print(f"MAC: {mac}")

                        # Extract the number of ports
                        num_ports_line = payload_lines[3]
                        num_ports = int(num_ports_line.split(": ")[1])
                        print(f"Number of Ports: {num_ports}")

                        # Extract the timestamp
                        timestamp_line = payload_lines[4]
                        timestamp = timestamp_line.split(": ")[1]
                        print(f"Timestamp: {timestamp}")

                        # Extract the port statistics
                        port_stats = []
                        for i in range(5, 5 + num_ports):
                            port_line = payload_lines[i]
                            port_stats.append(port_line)

                        print("Port Statistics:")
                        print(port_stats)
                        port_wise_statistics = {}
                        for port_stat in port_stats:
                            print(port_stat)
                            # Split the port statistics line
                            port_stat_parts = port_stat.split(", ")
                            port_id = port_stat_parts[0].split(" ")[1]
                            rxpkts = float(port_stat_parts[0].split("=")[1])
                            rxbytes = float(port_stat_parts[1].split("=")[1])
                            rxerrs = float(port_stat_parts[2].split("=")[1])
                            txpkts = float(port_stat_parts[3].split("=")[1])
                            txbytes = float(port_stat_parts[4].split("=")[1])
                            txerrs = float(port_stat_parts[5].split("=")[1])
                            rxutil = float(port_stat_parts[6].split("=")[1])
                            txutil = float(port_stat_parts[7].split("=")[1])
                            throughput = float(port_stat_parts[8].split("=")[1])
                            buffer_occ = float(port_stat_parts[9].split("=")[1])
                            checksum = float(port_stat_parts[10].split("=")[1])
                            # print(f"Port {port_id}: Rxpkts={rxpkts}, Rxbytes={rxbytes}, Rxerrs={rxerrs}, Txpkts={txpkts}, Txbytes={txbytes}, Txerrs={txerrs}")
                            # Verifying checksum
                            # Calculate checksum
                            # checksum = (
                            #     port['rxpkts'] + port['rxbytes'] + port['rxerrs'] +
                            #     port['txpkts'] + port['txbytes'] + port['txerrs'] +
                            #     port['rx_utilization'] + port['tx_utilization'] +
                            #     port['throughput (mbps)'] + port['buffer_occ']
                            # )
                            # Perform checksum operation
                            # checksum = checksum % 65536  # Ensure checksum is within 16-bit range
                            checksum_calc = (
                                rxpkts + rxbytes + rxerrs +
                                txpkts + txbytes + txerrs +
                                rxutil + txutil +
                                throughput + buffer_occ
                            )
                            # Perform checksum operation
                            checksum_calc = checksum_calc % 65536
                            if checksum != checksum_calc:
                                print(f"\n\n\n\n---------------------------------------------------\n\nChecksum mismatch for port {port_id}: {checksum} != {checksum_calc}\n\n")
                                continue
                            else:
                                print(f"Checksum match for port {port_id}: {checksum} == {checksum_calc}\n\n+++++++++++++++++++++\n\n\n\n")


                            port_wise_statistics[port_id] = {
                                'Rx Packets': rxpkts,
                                'Rx Bytes': rxbytes,
                                'Rx Errors': rxerrs,
                                'Tx Packets': txpkts,
                                'Tx Bytes': txbytes,
                                'Tx Errors': txerrs,
                                'Rx Utilization': rxutil,
                                'Tx Utilization': txutil,
                                'Throughput (Mbps)': throughput,
                                'Buffer Occupancy': buffer_occ
                            }
                            print(f"Port {port_id}: {port_wise_statistics[port_id]}")

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
                                'Total Rx Utilization': 0,
                                'Total Tx Utilization': 0,
                                'Total Throughput (Mbps)': 0,
                                'Total Buffer Occupancy': 0,
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
                                'Max Rx Utilization': float('-inf'),
                                'Min Rx Utilization': float('inf'),
                                'Max Tx Utilization': float('-inf'),
                                'Min Tx Utilization': float('inf'),
                                'Max Throughput (Mbps)': float('-inf'),
                                'Min Throughput (Mbps)': float('inf'),
                                'Max Buffer Occupancy': float('-inf'),
                                'Min Buffer Occupancy': float('inf'),
                                'Average Rx Packets': 0,
                                'Average Rx Bytes': 0,
                                'Average Rx Errors': 0,
                                'Average Tx Packets': 0,
                                'Average Tx Bytes': 0,
                                'Average Tx Errors': 0,
                                'Average Rx Utilization': 0,
                                'Average Tx Utilization': 0,
                                'Average Throughput (Mbps)': 0,
                                'Average Buffer Occupancy': 0
                            }
                        
                        # Update the timestamps
                        switch_wise_statistics[mac]['Latest Timestamp'] = max(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), switch_wise_statistics[mac]['Latest Timestamp'])
                        switch_wise_statistics[mac]['Oldest Timestamp'] = min(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), switch_wise_statistics[mac]['Oldest Timestamp'])

                        # Update the statistics
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
                            switch_wise_statistics[mac]['Total Rx Utilization'] += port_stat['Rx Utilization']
                            switch_wise_statistics[mac]['Total Tx Utilization'] += port_stat['Tx Utilization']
                            switch_wise_statistics[mac]['Total Throughput (Mbps)'] += port_stat['Throughput (Mbps)']
                            switch_wise_statistics[mac]['Total Buffer Occupancy'] += port_stat['Buffer Occupancy']

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
                            switch_wise_statistics[mac]['Min Rx Utilization'] = min(switch_wise_statistics[mac]['Min Rx Utilization'], port_stat['Rx Utilization'])
                            switch_wise_statistics[mac]['Max Rx Utilization'] = max(switch_wise_statistics[mac]['Max Rx Utilization'], port_stat['Rx Utilization'])
                            switch_wise_statistics[mac]['Min Tx Utilization'] = min(switch_wise_statistics[mac]['Min Tx Utilization'], port_stat['Tx Utilization'])
                            switch_wise_statistics[mac]['Max Tx Utilization'] = max(switch_wise_statistics[mac]['Max Tx Utilization'], port_stat['Tx Utilization'])
                            switch_wise_statistics[mac]['Min Throughput (Mbps)'] = min(switch_wise_statistics[mac]['Min Throughput (Mbps)'], port_stat['Throughput (Mbps)'])
                            switch_wise_statistics[mac]['Max Throughput (Mbps)'] = max(switch_wise_statistics[mac]['Max Throughput (Mbps)'], port_stat['Throughput (Mbps)'])
                            switch_wise_statistics[mac]['Min Buffer Occupancy'] = min(switch_wise_statistics[mac]['Min Buffer Occupancy'], port_stat['Buffer Occupancy'])
                            switch_wise_statistics[mac]['Max Buffer Occupancy'] = max(switch_wise_statistics[mac]['Max Buffer Occupancy'], port_stat['Buffer Occupancy'])

                        switch_wise_statistics[mac]['Average Rx Packets'] = switch_wise_statistics[mac]['Total Rx Packets'] / num_ports
                        switch_wise_statistics[mac]['Average Rx Bytes'] = switch_wise_statistics[mac]['Total Rx Bytes'] / num_ports
                        switch_wise_statistics[mac]['Average Rx Errors'] = switch_wise_statistics[mac]['Total Rx Errors'] / num_ports
                        switch_wise_statistics[mac]['Average Tx Packets'] = switch_wise_statistics[mac]['Total Tx Packets'] / num_ports
                        switch_wise_statistics[mac]['Average Tx Bytes'] = switch_wise_statistics[mac]['Total Tx Bytes'] / num_ports
                        switch_wise_statistics[mac]['Average Tx Errors'] = switch_wise_statistics[mac]['Total Tx Errors'] / num_ports
                        switch_wise_statistics[mac]['Average Rx Utilization'] = switch_wise_statistics[mac]['Total Rx Utilization'] / num_ports
                        switch_wise_statistics[mac]['Average Tx Utilization'] = switch_wise_statistics[mac]['Total Tx Utilization'] / num_ports
                        switch_wise_statistics[mac]['Average Throughput (Mbps)'] = switch_wise_statistics[mac]['Total Throughput (Mbps)'] / num_ports
                        switch_wise_statistics[mac]['Average Buffer Occupancy'] = switch_wise_statistics[mac]['Total Buffer Occupancy'] / num_ports

                        # print("-" * 20)

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return switch_wise_statistics

def find_router_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and prints the entire packet if it contains "PACKET STARTED" or "PACKET ENDED".

    Args:
        pcap_file (str): The path to the pcap file.
    """
    router_wise_statistics = {} # This is a dictionary of dictionaries. The outer dictionary is indexed by the MAC address of the router. The inner dictionary is indexed by the following fieds
    # 'Number of Interfaces', 'Latest Timestamp', 'Oldest Timestamp', 'Total Packets', 'Total Bytes', 'Total Errors', 'Total Rx Packets', 'Total Rx Bytes', 'Total Rx Errors', 'Total Tx Packets', 'Total Tx Bytes', 'Total Tx Errors'
    # 'Min Rx Packets', 'Max Rx Packets', 'Min Rx Bytes', 'Max Rx Bytes', 'Min Rx Errors', 'Max Rx Errors', 'Min Tx Packets', 'Max Tx Packets', 'Min Tx Bytes', 'Max Tx Bytes', 'Min Tx Errors', 'Max Tx Errors'
    # 'Average Rx Packets', 'Average Rx Bytes', 'Average Rx Errors', 'Average Tx Packets', 'Average Tx Bytes', 'Average Tx Errors'
    # This is added to the dictionary if the packet contains "PACKET STARTED" or "PACKET ENDED" and has Is Switch: True. We will update this dictionary as we go through the packets.

    try:
        packets = rdpcap(pcap_file)

        for packet_number, packet in enumerate(packets):
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')

                if "PACKET STARTED" in payload or "PACKET ENDED" in payload:
                    # Append time to the file
                    # with open("Hello1.txt", "a") as f:
                    #     f.write(str(datetime.datetime.now()))
                    # print(f"Packet Number: {packet_number + 1}") # Scapy packets are 0-indexed.
                    # Show only the load
                    # print(payload)
                    # Split the payload according to this:
                    # Packet Number: 22
                    # 55PACKET STARTED
                    # Is Switch: True
                    # MAC: 72:1d:b6:88:ef:41
                    # Number of Ports: 4
                    # Timestamp: 2025-03-22 06:27:13.182
                    # Port 4: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 1: Rxpkts=0, Rxbytes=77, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 2: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=0, Txerrs=0
                    # Port 3: Rxpkts=0, Rxbytes=0, Rxerrs=0, Txpkts=0, Txbytes=77, Txerrs=0
                    # PACKET ENDED

                    # Split the payload into lines
                    payload_lines = payload.split("\n")
                    #Print line numbers
                    for i, line in enumerate(payload_lines):
                        print(f"{i+1}: {line}")

                    if payload_lines[1].split(": ")[1] == "False":

                        # Extract the MAC address
                        mac_line = payload_lines[2]
                        mac = mac_line.split(": ")[1]
                        print(f"MAC: {mac}")

                        # Extract the number of interfaces
                        num_intf_line = payload_lines[3]
                        num_intf = int(num_intf_line.split(": ")[1])
                        print(f"Number of Interfaces: {num_intf}")

                        # Extract the timestamp
                        timestamp_line = payload_lines[4]
                        timestamp = timestamp_line.split(": ")[1]
                        print(f"Timestamp: {timestamp}")

                        intf_stats = []
                        for i in range(5, 5 + num_intf):
                            intf_line = payload_lines[i]
                            intf_stats.append(intf_line)

                        print("Interface Statistics:")
                        print(intf_stats)
                        intf_wise_statistics = {}
                        for intf_stat in intf_stats:
                            print(intf_stat)
                            # Split the port statistics line
                            intf_stat_parts = intf_stat.split(", ")
                            intf_id = intf_stat_parts[0].split(" ")[1].split(":")[0]
                            rxpkts = float(intf_stat_parts[0].split("=")[1])
                            rxbytes = float(intf_stat_parts[1].split("=")[1])
                            rxerrs = float(intf_stat_parts[2].split("=")[1])
                            txpkts = float(intf_stat_parts[3].split("=")[1])
                            txbytes = float(intf_stat_parts[4].split("=")[1])
                            txerrs = float(intf_stat_parts[5].split("=")[1])
                            rxutil = float(intf_stat_parts[6].split("=")[1])
                            txutil = float(intf_stat_parts[7].split("=")[1])
                            throughput = float(intf_stat_parts[8].split("=")[1])
                            buffer_occ = float(intf_stat_parts[9].split("=")[1])
                            checksum = float(intf_stat_parts[10].split("=")[1])
                            
                            checksum_calc = (
                                rxpkts + rxbytes + rxerrs +
                                txpkts + txbytes + txerrs +
                                rxutil + txutil +
                                throughput + buffer_occ
                            )
                            # Perform checksum operation
                            checksum_calc = checksum_calc % 65536
                            if checksum != checksum_calc:
                                print(f"\n\n\n\n---------------------------------------------------\n\nChecksum mismatch for interface {intf_id}: {checksum} != {checksum_calc}\n\n")
                                continue
                            else:
                                print(f"Checksum match for interface {intf_id}: {checksum} == {checksum_calc}\n\n+++++++++++++++++++++\n\n\n\n")


                            intf_wise_statistics[intf_id] = {
                                'Rx Packets': rxpkts,
                                'Rx Bytes': rxbytes,
                                'Rx Errors': rxerrs,
                                'Tx Packets': txpkts,
                                'Tx Bytes': txbytes,
                                'Tx Errors': txerrs,
                                'Rx Utilization': rxutil,
                                'Tx Utilization': txutil,
                                'Throughput (Mbps)': throughput,
                                'Buffer Occupancy': buffer_occ
                            }
                            print(f"Interface {intf_id}: {intf_wise_statistics[intf_id]}")

                        if mac not in router_wise_statistics:
                            router_wise_statistics[mac] = {
                                'Number of Interfaces': num_intf,
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
                                'Total Rx Utilization': 0,
                                'Total Tx Utilization': 0,
                                'Total Throughput (Mbps)': 0,
                                'Total Buffer Occupancy': 0,
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
                                'Max Rx Utilization': float('-inf'),
                                'Min Rx Utilization': float('inf'),
                                'Max Tx Utilization': float('-inf'),
                                'Min Tx Utilization': float('inf'),
                                'Max Throughput (Mbps)': float('-inf'),
                                'Min Throughput (Mbps)': float('inf'),
                                'Max Buffer Occupancy': float('-inf'),
                                'Min Buffer Occupancy': float('inf'),
                                'Average Rx Packets': 0,
                                'Average Rx Bytes': 0,
                                'Average Rx Errors': 0,
                                'Average Tx Packets': 0,
                                'Average Tx Bytes': 0,
                                'Average Tx Errors': 0,
                                'Average Rx Utilization': 0,
                                'Average Tx Utilization': 0,
                                'Average Throughput (Mbps)': 0,
                                'Average Buffer Occupancy': 0
                            }
                        
                        # Update the timestamps
                        router_wise_statistics[mac]['Latest Timestamp'] = max(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), router_wise_statistics[mac]['Latest Timestamp'])
                        router_wise_statistics[mac]['Oldest Timestamp'] = min(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), router_wise_statistics[mac]['Oldest Timestamp'])

                        # Update the statistics
                        for intf_id, intf_stat in intf_wise_statistics.items():
                            router_wise_statistics[mac]['Total Packets'] += intf_stat['Rx Packets'] + intf_stat['Tx Packets']
                            router_wise_statistics[mac]['Total Bytes'] += intf_stat['Rx Bytes'] + intf_stat['Tx Bytes']
                            router_wise_statistics[mac]['Total Errors'] += intf_stat['Rx Errors'] + intf_stat['Tx Errors']
                            router_wise_statistics[mac]['Total Rx Packets'] += intf_stat['Rx Packets']
                            router_wise_statistics[mac]['Total Rx Bytes'] += intf_stat['Rx Bytes']
                            router_wise_statistics[mac]['Total Rx Errors'] += intf_stat['Rx Errors']
                            router_wise_statistics[mac]['Total Tx Packets'] += intf_stat['Tx Packets']
                            router_wise_statistics[mac]['Total Tx Bytes'] += intf_stat['Tx Bytes']
                            router_wise_statistics[mac]['Total Tx Errors'] += intf_stat['Tx Errors']
                            router_wise_statistics[mac]['Total Rx Utilization'] += intf_stat['Rx Utilization']
                            router_wise_statistics[mac]['Total Tx Utilization'] += intf_stat['Tx Utilization']
                            router_wise_statistics[mac]['Total Throughput (Mbps)'] += intf_stat['Throughput (Mbps)']
                            router_wise_statistics[mac]['Total Buffer Occupancy'] += intf_stat['Buffer Occupancy']

                            router_wise_statistics[mac]['Min Rx Packets'] = min(router_wise_statistics[mac]['Min Rx Packets'], intf_stat['Rx Packets'])
                            router_wise_statistics[mac]['Max Rx Packets'] = max(router_wise_statistics[mac]['Max Rx Packets'], intf_stat['Rx Packets'])
                            router_wise_statistics[mac]['Min Rx Bytes'] = min(router_wise_statistics[mac]['Min Rx Bytes'], intf_stat['Rx Bytes'])
                            router_wise_statistics[mac]['Max Rx Bytes'] = max(router_wise_statistics[mac]['Max Rx Bytes'], intf_stat['Rx Bytes'])
                            router_wise_statistics[mac]['Min Rx Errors'] = min(router_wise_statistics[mac]['Min Rx Errors'], intf_stat['Rx Errors'])
                            router_wise_statistics[mac]['Max Rx Errors'] = max(router_wise_statistics[mac]['Max Rx Errors'], intf_stat['Rx Errors'])
                            router_wise_statistics[mac]['Min Tx Packets'] = min(router_wise_statistics[mac]['Min Tx Packets'], intf_stat['Tx Packets'])
                            router_wise_statistics[mac]['Max Tx Packets'] = max(router_wise_statistics[mac]['Max Tx Packets'], intf_stat['Tx Packets'])
                            router_wise_statistics[mac]['Min Tx Bytes'] = min(router_wise_statistics[mac]['Min Tx Bytes'], intf_stat['Tx Bytes'])
                            router_wise_statistics[mac]['Max Tx Bytes'] = max(router_wise_statistics[mac]['Max Tx Bytes'], intf_stat['Tx Bytes'])
                            router_wise_statistics[mac]['Min Tx Errors'] = min(router_wise_statistics[mac]['Min Tx Errors'], intf_stat['Tx Errors'])
                            router_wise_statistics[mac]['Max Tx Errors'] = max(router_wise_statistics[mac]['Max Tx Errors'], intf_stat['Tx Errors'])
                            router_wise_statistics[mac]['Min Rx Utilization'] = min(router_wise_statistics[mac]['Min Rx Utilization'], intf_stat['Rx Utilization'])
                            router_wise_statistics[mac]['Max Rx Utilization'] = max(router_wise_statistics[mac]['Max Rx Utilization'], intf_stat['Rx Utilization'])
                            router_wise_statistics[mac]['Min Tx Utilization'] = min(router_wise_statistics[mac]['Min Tx Utilization'], intf_stat['Tx Utilization'])
                            router_wise_statistics[mac]['Max Tx Utilization'] = max(router_wise_statistics[mac]['Max Tx Utilization'], intf_stat['Tx Utilization'])
                            router_wise_statistics[mac]['Min Throughput (Mbps)'] = min(router_wise_statistics[mac]['Min Throughput (Mbps)'], intf_stat['Throughput (Mbps)'])
                            router_wise_statistics[mac]['Max Throughput (Mbps)'] = max(router_wise_statistics[mac]['Max Throughput (Mbps)'], intf_stat['Throughput (Mbps)'])
                            router_wise_statistics[mac]['Min Buffer Occupancy'] = min(router_wise_statistics[mac]['Min Buffer Occupancy'], intf_stat['Buffer Occupancy'])
                            router_wise_statistics[mac]['Max Buffer Occupancy'] = max(router_wise_statistics[mac]['Max Buffer Occupancy'], intf_stat['Buffer Occupancy'])

                        router_wise_statistics[mac]['Average Rx Packets'] = router_wise_statistics[mac]['Total Rx Packets'] / num_intf
                        router_wise_statistics[mac]['Average Rx Bytes'] = router_wise_statistics[mac]['Total Rx Bytes'] / num_intf
                        router_wise_statistics[mac]['Average Rx Errors'] = router_wise_statistics[mac]['Total Rx Errors'] / num_intf
                        router_wise_statistics[mac]['Average Tx Packets'] = router_wise_statistics[mac]['Total Tx Packets'] / num_intf
                        router_wise_statistics[mac]['Average Tx Bytes'] = router_wise_statistics[mac]['Total Tx Bytes'] / num_intf
                        router_wise_statistics[mac]['Average Tx Errors'] = router_wise_statistics[mac]['Total Tx Errors'] / num_intf
                        router_wise_statistics[mac]['Average Rx Utilization'] = router_wise_statistics[mac]['Total Rx Utilization'] / num_intf
                        router_wise_statistics[mac]['Average Tx Utilization'] = router_wise_statistics[mac]['Total Tx Utilization'] / num_intf
                        router_wise_statistics[mac]['Average Throughput (Mbps)'] = router_wise_statistics[mac]['Total Throughput (Mbps)'] / num_intf
                        router_wise_statistics[mac]['Average Buffer Occupancy'] = router_wise_statistics[mac]['Total Buffer Occupancy'] / num_intf

                        # print("-" * 20)

    except FileNotFoundError:
        print(f"Error: File '{pcap_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return router_wise_statistics

def find_router_rules_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and extracts router telemetry packets by looking for
    "ROUTER PACKET STARTED" and "ROUTER PACKET ENDED" in the payload.
    Returns a dictionary keyed by the router's MAC address with the following fields:
      - "Number of Routes"
      - "Timestamp"
      - "Routes": a list of route lines (each starting with "Route:" or "Routing Protocols:")
    """
    router_statistics = {}
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "ROUTER PACKET STARTED" in payload and "ROUTER PACKET ENDED" in payload:
                    lines = payload.split("\n")
                    mac_line = next((line for line in lines if line.startswith("MAC:")), None)
                    if mac_line:
                        mac = mac_line.split("MAC:")[1].strip()
                        num_routes_line = next((line for line in lines if line.startswith("Number of Routes:")), None)
                        num_routes = num_routes_line.split("Number of Routes:")[1].strip() if num_routes_line else "N/A"
                        timestamp_line = next((line for line in lines if line.startswith("Timestamp:")), None)
                        timestamp = timestamp_line.split("Timestamp:")[1].strip() if timestamp_line else "N/A"
                        # Collect route lines: lines that start with "Route:" or "Routing Protocols:"
                        route_lines = [line.strip() for line in lines if line.startswith("Route:") or line.startswith("Routing Protocols:")]
                        router_statistics[mac] = {
                            "Number of Routes": num_routes,
                            "Timestamp": timestamp,
                            "Routes": route_lines
                        }
        return router_statistics
    except Exception as e:
        print(f"An error occurred while processing the pcap file: {e}")
        return router_statistics

def find_firewall_packets_scapy(pcap_file):
    fw_stats = {}
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "FIREWALL PACKET STARTED" in payload and "FIREWALL PACKET ENDED" in payload:
                    payload_lines = payload.split("\n")

                    #Print line numbers
                    for i, line in enumerate(payload_lines):
                        print(f"{i+1}: {line}")

                    # Extract the MAC address
                    mac_line = payload_lines[2]
                    mac = mac_line.split(": ")[1]

                    num_intf_line = payload_lines[3]
                    num_intf = int(num_intf_line.split(": ")[1])

                    # Extract the timestamp
                    timestamp_line = payload_lines[4]
                    timestamp = timestamp_line.split(": ")[1]

                    # Extract the port statistics
                    intf_stats = []
                    for i in range(5, 5 + num_intf):
                        intf_line = payload_lines[i]
                        intf_stats.append(intf_line)
                
                    print("Interface Statistics:")
                    print(intf_stats)
                    intf_wise_statistics = {}
                    for intf_stat in intf_stats:
                        print(intf_stat)
                        # Split the port statistics line
                        intf_stat_parts = intf_stat.split(", ")
                        intf_id = intf_stat_parts[0].split(" ")[1].split(":")[0]
                        rxpkts = float(intf_stat_parts[0].split("=")[1])
                        rxbytes = float(intf_stat_parts[1].split("=")[1])
                        rxerrs = float(intf_stat_parts[2].split("=")[1])
                        txpkts = float(intf_stat_parts[3].split("=")[1])
                        txbytes = float(intf_stat_parts[4].split("=")[1])
                        txerrs = float(intf_stat_parts[5].split("=")[1])
                        rxutil = float(intf_stat_parts[6].split("=")[1])
                        txutil = float(intf_stat_parts[7].split("=")[1])
                        throughput = float(intf_stat_parts[8].split("=")[1])
                        buffer_occ = float(intf_stat_parts[9].split("=")[1])
                        checksum = float(intf_stat_parts[10].split("=")[1])
                        
                        checksum_calc = (
                            rxpkts + rxbytes + rxerrs +
                            txpkts + txbytes + txerrs +
                            rxutil + txutil +
                            throughput + buffer_occ
                        )
                        # Perform checksum operation
                        checksum_calc = checksum_calc % 65536
                        if checksum != checksum_calc:
                            print(f"\n\n\n\n---------------------------------------------------\n\nChecksum mismatch for interface {intf_id}: {checksum} != {checksum_calc}\n\n")
                            continue
                        else:
                            print(f"Checksum match for interface {intf_id}: {checksum} == {checksum_calc}\n\n+++++++++++++++++++++\n\n\n\n")


                        intf_wise_statistics[intf_id] = {
                            'Rx Packets': rxpkts,
                            'Rx Bytes': rxbytes,
                            'Rx Errors': rxerrs,
                            'Tx Packets': txpkts,
                            'Tx Bytes': txbytes,
                            'Tx Errors': txerrs,
                            'Rx Utilization': rxutil,
                            'Tx Utilization': txutil,
                            'Throughput (Mbps)': throughput,
                            'Buffer Occupancy': buffer_occ
                        }
                        print(f"Interface {intf_id}: {intf_wise_statistics[intf_id]}")

                    if mac not in fw_stats:
                        fw_stats[mac] = {
                            'Number of Interfaces': num_intf,
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
                            'Total Rx Utilization': 0,
                            'Total Tx Utilization': 0,
                            'Total Throughput (Mbps)': 0,
                            'Total Buffer Occupancy': 0,
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
                            'Max Rx Utilization': float('-inf'),
                            'Min Rx Utilization': float('inf'),
                            'Max Tx Utilization': float('-inf'),
                            'Min Tx Utilization': float('inf'),
                            'Max Throughput (Mbps)': float('-inf'),
                            'Min Throughput (Mbps)': float('inf'),
                            'Max Buffer Occupancy': float('-inf'),
                            'Min Buffer Occupancy': float('inf'),
                            'Average Rx Packets': 0,
                            'Average Rx Bytes': 0,
                            'Average Rx Errors': 0,
                            'Average Tx Packets': 0,
                            'Average Tx Bytes': 0,
                            'Average Tx Errors': 0,
                            'Average Rx Utilization': 0,
                            'Average Tx Utilization': 0,
                            'Average Throughput (Mbps)': 0,
                            'Average Buffer Occupancy': 0
                        }
                    
                    # Update the timestamps
                    fw_stats[mac]['Latest Timestamp'] = max(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), fw_stats[mac]['Latest Timestamp'])
                    fw_stats[mac]['Oldest Timestamp'] = min(datetime.datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f"), fw_stats[mac]['Oldest Timestamp'])

                    # Update the statistics
                    for intf_id, intf_stat in intf_wise_statistics.items():
                        fw_stats[mac]['Total Packets'] += intf_stat['Rx Packets'] + intf_stat['Tx Packets']
                        fw_stats[mac]['Total Bytes'] += intf_stat['Rx Bytes'] + intf_stat['Tx Bytes']
                        fw_stats[mac]['Total Errors'] += intf_stat['Rx Errors'] + intf_stat['Tx Errors']
                        fw_stats[mac]['Total Rx Packets'] += intf_stat['Rx Packets']
                        fw_stats[mac]['Total Rx Bytes'] += intf_stat['Rx Bytes']
                        fw_stats[mac]['Total Rx Errors'] += intf_stat['Rx Errors']
                        fw_stats[mac]['Total Tx Packets'] += intf_stat['Tx Packets']
                        fw_stats[mac]['Total Tx Bytes'] += intf_stat['Tx Bytes']
                        fw_stats[mac]['Total Tx Errors'] += intf_stat['Tx Errors']
                        fw_stats[mac]['Total Rx Utilization'] += intf_stat['Rx Utilization']
                        fw_stats[mac]['Total Tx Utilization'] += intf_stat['Tx Utilization']
                        fw_stats[mac]['Total Throughput (Mbps)'] += intf_stat['Throughput (Mbps)']
                        fw_stats[mac]['Total Buffer Occupancy'] += intf_stat['Buffer Occupancy']

                        fw_stats[mac]['Min Rx Packets'] = min(fw_stats[mac]['Min Rx Packets'], intf_stat['Rx Packets'])
                        fw_stats[mac]['Max Rx Packets'] = max(fw_stats[mac]['Max Rx Packets'], intf_stat['Rx Packets'])
                        fw_stats[mac]['Min Rx Bytes'] = min(fw_stats[mac]['Min Rx Bytes'], intf_stat['Rx Bytes'])
                        fw_stats[mac]['Max Rx Bytes'] = max(fw_stats[mac]['Max Rx Bytes'], intf_stat['Rx Bytes'])
                        fw_stats[mac]['Min Rx Errors'] = min(fw_stats[mac]['Min Rx Errors'], intf_stat['Rx Errors'])
                        fw_stats[mac]['Max Rx Errors'] = max(fw_stats[mac]['Max Rx Errors'], intf_stat['Rx Errors'])
                        fw_stats[mac]['Min Tx Packets'] = min(fw_stats[mac]['Min Tx Packets'], intf_stat['Tx Packets'])
                        fw_stats[mac]['Max Tx Packets'] = max(fw_stats[mac]['Max Tx Packets'], intf_stat['Tx Packets'])
                        fw_stats[mac]['Min Tx Bytes'] = min(fw_stats[mac]['Min Tx Bytes'], intf_stat['Tx Bytes'])
                        fw_stats[mac]['Max Tx Bytes'] = max(fw_stats[mac]['Max Tx Bytes'], intf_stat['Tx Bytes'])
                        fw_stats[mac]['Min Tx Errors'] = min(fw_stats[mac]['Min Tx Errors'], intf_stat['Tx Errors'])
                        fw_stats[mac]['Max Tx Errors'] = max(fw_stats[mac]['Max Tx Errors'], intf_stat['Tx Errors'])
                        fw_stats[mac]['Min Rx Utilization'] = min(fw_stats[mac]['Min Rx Utilization'], intf_stat['Rx Utilization'])
                        fw_stats[mac]['Max Rx Utilization'] = max(fw_stats[mac]['Max Rx Utilization'], intf_stat['Rx Utilization'])
                        fw_stats[mac]['Min Tx Utilization'] = min(fw_stats[mac]['Min Tx Utilization'], intf_stat['Tx Utilization'])
                        fw_stats[mac]['Max Tx Utilization'] = max(fw_stats[mac]['Max Tx Utilization'], intf_stat['Tx Utilization'])
                        fw_stats[mac]['Min Throughput (Mbps)'] = min(fw_stats[mac]['Min Throughput (Mbps)'], intf_stat['Throughput (Mbps)'])
                        fw_stats[mac]['Max Throughput (Mbps)'] = max(fw_stats[mac]['Max Throughput (Mbps)'], intf_stat['Throughput (Mbps)'])
                        fw_stats[mac]['Min Buffer Occupancy'] = min(fw_stats[mac]['Min Buffer Occupancy'], intf_stat['Buffer Occupancy'])
                        fw_stats[mac]['Max Buffer Occupancy'] = max(fw_stats[mac]['Max Buffer Occupancy'], intf_stat['Buffer Occupancy'])

                    fw_stats[mac]['Average Rx Packets'] = fw_stats[mac]['Total Rx Packets'] / num_intf
                    fw_stats[mac]['Average Rx Bytes'] = fw_stats[mac]['Total Rx Bytes'] / num_intf
                    fw_stats[mac]['Average Rx Errors'] = fw_stats[mac]['Total Rx Errors'] / num_intf
                    fw_stats[mac]['Average Tx Packets'] = fw_stats[mac]['Total Tx Packets'] / num_intf
                    fw_stats[mac]['Average Tx Bytes'] = fw_stats[mac]['Total Tx Bytes'] / num_intf
                    fw_stats[mac]['Average Tx Errors'] = fw_stats[mac]['Total Tx Errors'] / num_intf
                    fw_stats[mac]['Average Rx Utilization'] = fw_stats[mac]['Total Rx Utilization'] / num_intf
                    fw_stats[mac]['Average Tx Utilization'] = fw_stats[mac]['Total Tx Utilization'] / num_intf
                    fw_stats[mac]['Average Throughput (Mbps)'] = fw_stats[mac]['Total Throughput (Mbps)'] / num_intf
                    fw_stats[mac]['Average Buffer Occupancy'] = fw_stats[mac]['Total Buffer Occupancy'] / num_intf
        return fw_stats
    except Exception as e:
        print(f"Error processing firewall health packets: {e}")
        return fw_stats

def find_firewall_rules_packets_scapy(pcap_file):
    """
    Reads a pcap file using Scapy and extracts firewall rules telemetry packets.
    These packets are expected to contain the markers "FIREWALL RULES PACKET STARTED"
    and "FIREWALL RULES PACKET ENDED".
    Returns a dictionary keyed by the firewall's MAC address with fields:
       - "Number of Rule Lines"
       - "Timestamp"
       - "Rule Details": a list of the rule lines.
    """
    fw_rule_stats = {}
    try:
        packets = rdpcap(pcap_file)
        for packet in packets:
            if Raw in packet:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if "FIREWALL RULES PACKET STARTED" in payload and "FIREWALL RULES PACKET ENDED" in payload:
                    payload_lines = payload.split("\n")

                    #Print line numbers
                    for i, line in enumerate(payload_lines):
                        print(f"{i+1}: {line}")

                    # Extract the MAC address
                    mac_line = payload_lines[2]
                    mac = mac_line.split(": ")[1]

                    timestamp_line = next((line for line in payload_lines if line.startswith("Timestamp:")), None)
                    timestamp = timestamp_line.split("Timestamp:")[1].strip() if timestamp_line else "N/A"
                    # After the header, we assume a line "Firewall Rules:" exists; then the rule details follow.
                    try:
                        idx = payload_lines.index("Firewall Rules:") + 1
                    except ValueError:
                        idx = 0
                    rule_lines = [line.strip() for line in payload_lines[idx:] 
                                  if line.strip() and "FIREWALL RULES PACKET ENDED" not in line and "Checksum:" not in line]
                    num_rules = len(rule_lines)
                    fw_rule_stats[mac] = {
                        "Number of Rule Lines": num_rules,
                        "Timestamp": timestamp,
                        "Rule Details": rule_lines
                    }
        return fw_rule_statss
    except Exception as e:
        print(f"Error processing firewall rules packets: {e}")
        return fw_rule_stats

def craft_to_cc2dc_switch_protocol_payload(swstats, CC_Name):
    """
    Craft the packets to send to the Data Center using the CC2DC protocol."
    """
    # CC_Name: CC1
    # Number Of Devices: 8b
    # Time: YYYY-MM-DDTHH:mm:ss.SSS GMT
    # For every Device:
    #     'MAC': '72:1d:b6:88:ef:41'
    #     'Number of Ports': 4, 
    #     'Latest Timestamp': datetime.datetime(2025, 3, 22, 6, 27, 13, 182000)
    #     'Oldest Timestamp': datetime.datetime(2025, 3, 22, 6, 26, 50, 164000)
    #     'Total Packets': 45
    #     'Total Bytes': 7031
    #     'Total Errors': 0
    #     'Total Rx Packets': 3
    #     'Total Rx Bytes': 1200
    #     'Total Rx Errors': 0
    #     'Total Tx Packets': 42
    #     'Total Tx Bytes': 5831
    #     'Total Tx Errors': 0
    #     'Total Rx Utilization': 0
    #     'Total Tx Utilization': 0
    #     'Total Throughput (Mbps)': 0
    #     'Total Buffer Occupancy': 0
    #     'Min Rx Packets': 0
    #     'Max Rx Packets': 1
    #     'Min Rx Bytes': 0
    #     'Max Rx Bytes': 175
    #     'Min Rx Errors': 0
    #     'Max Rx Errors': 0
    #     'Min Tx Packets': 0
    #     'Max Tx Packets': 7
    #     'Min Tx Bytes': 0,
    #     'Max Tx Bytes': 718
    #     'Min Tx Errors': 0
    #     'Max Tx Errors': 0
    #     'Min Rx Utilization': 0
    #     'Max Rx Utilization': 0
    #     'Min Tx Utilization': 0
    #     'Max Tx Utilization': 0
    #     'Min Throughput (Mbps)': 0
    #     'Max Throughput (Mbps)': 0
    #     'Min Buffer Occupancy': 0
    #     'Max Buffer Occupancy': 0
    #     'Average Rx Packets': 0.75
    #     'Average Rx Bytes': 300.0
    #     'Average Rx Errors': 0.0
    #     'Average Tx Packets': 10.5
    #     'Average Tx Bytes': 1457.75
    #     'Average Tx Errors': 0.0
    #     'Average Rx Utilization': 0.0
    #     'Average Tx Utilization': 0.0
    #     'Average Throughput (Mbps)': 0.0
    #     'Average Buffer Occupancy': 0.0
    # We will put this into the TCP Payload

    # Create the CC2DC packet payload
    timenow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    tcppayload = "CC2DC SWITCH PACKET STARTED\n"
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
        tcppayload += f"{stats['Total Rx Utilization']}\n"
        tcppayload += f"{stats['Total Tx Utilization']}\n"
        tcppayload += f"{stats['Total Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Total Buffer Occupancy']}\n"
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
        tcppayload += f"{stats['Min Rx Utilization']}\n"
        tcppayload += f"{stats['Max Rx Utilization']}\n"
        tcppayload += f"{stats['Min Tx Utilization']}\n"
        tcppayload += f"{stats['Max Tx Utilization']}\n"
        tcppayload += f"{stats['Min Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Max Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Min Buffer Occupancy']}\n"
        tcppayload += f"{stats['Max Buffer Occupancy']}\n"
        tcppayload += f"{stats['Average Rx Packets']}\n"
        tcppayload += f"{stats['Average Rx Bytes']}\n"
        tcppayload += f"{stats['Average Rx Errors']}\n"
        tcppayload += f"{stats['Average Tx Packets']}\n"
        tcppayload += f"{stats['Average Tx Bytes']}\n"
        tcppayload += f"{stats['Average Tx Errors']}\n"
        tcppayload += f"{stats['Average Rx Utilization']}\n"
        tcppayload += f"{stats['Average Tx Utilization']}\n"
        tcppayload += f"{stats['Average Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Average Buffer Occupancy']}\n"
    # Add a checksum for the entire payload
    checksum = sum([ord(c) for c in tcppayload]) % 65536
    tcppayload += f"Checksum: {checksum}\n"
    tcppayload += "CC2DC SWITCH PACKET ENDED\n\n"


    return tcppayload

def craft_to_cc2dc_router_protocol_payload(rtstats, CC_Name):
    """
    Craft the packets to send to the Data Center using the CC2DC protocol."
    """
    # CC_Name: CC1
    # Number Of Devices: 8b
    # Time: YYYY-MM-DDTHH:mm:ss.SSS GMT
    # For every Device:
    #     'MAC': '72:1d:b6:88:ef:41'
    #     'Number of Ports': 4, 
    #     'Latest Timestamp': datetime.datetime(2025, 3, 22, 6, 27, 13, 182000)
    #     'Oldest Timestamp': datetime.datetime(2025, 3, 22, 6, 26, 50, 164000)
    #     'Total Packets': 45
    #     'Total Bytes': 7031
    #     'Total Errors': 0
    #     'Total Rx Packets': 3
    #     'Total Rx Bytes': 1200
    #     'Total Rx Errors': 0
    #     'Total Tx Packets': 42
    #     'Total Tx Bytes': 5831
    #     'Total Tx Errors': 0
    #     'Total Rx Utilization': 0
    #     'Total Tx Utilization': 0
    #     'Total Throughput (Mbps)': 0
    #     'Total Buffer Occupancy': 0
    #     'Min Rx Packets': 0
    #     'Max Rx Packets': 1
    #     'Min Rx Bytes': 0
    #     'Max Rx Bytes': 175
    #     'Min Rx Errors': 0
    #     'Max Rx Errors': 0
    #     'Min Tx Packets': 0
    #     'Max Tx Packets': 7
    #     'Min Tx Bytes': 0,
    #     'Max Tx Bytes': 718
    #     'Min Tx Errors': 0
    #     'Max Tx Errors': 0
    #     'Min Rx Utilization': 0
    #     'Max Rx Utilization': 0
    #     'Min Tx Utilization': 0
    #     'Max Tx Utilization': 0
    #     'Min Throughput (Mbps)': 0
    #     'Max Throughput (Mbps)': 0
    #     'Min Buffer Occupancy': 0
    #     'Max Buffer Occupancy': 0
    #     'Average Rx Packets': 0.75
    #     'Average Rx Bytes': 300.0
    #     'Average Rx Errors': 0.0
    #     'Average Tx Packets': 10.5
    #     'Average Tx Bytes': 1457.75
    #     'Average Tx Errors': 0.0
    #     'Average Rx Utilization': 0.0
    #     'Average Tx Utilization': 0.0
    #     'Average Throughput (Mbps)': 0.0
    #     'Average Buffer Occupancy': 0.0
    # We will put this into the TCP Payload

    # Create the CC2DC packet payload
    timenow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    tcppayload = "CC2DC ROUTER PACKET STARTED\n"
    tcppayload += f"{CC_Name}\n"
    tcppayload += f"{len(rtstats)}\n"
    tcppayload += f"{timenow}\n"
    for mac, stats in rtstats.items():
        tcppayload += f"{mac}\n"
        tcppayload += f"{stats['Number of Interfaces']}\n"
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
        tcppayload += f"{stats['Total Rx Utilization']}\n"
        tcppayload += f"{stats['Total Tx Utilization']}\n"
        tcppayload += f"{stats['Total Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Total Buffer Occupancy']}\n"
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
        tcppayload += f"{stats['Min Rx Utilization']}\n"
        tcppayload += f"{stats['Max Rx Utilization']}\n"
        tcppayload += f"{stats['Min Tx Utilization']}\n"
        tcppayload += f"{stats['Max Tx Utilization']}\n"
        tcppayload += f"{stats['Min Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Max Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Min Buffer Occupancy']}\n"
        tcppayload += f"{stats['Max Buffer Occupancy']}\n"
        tcppayload += f"{stats['Average Rx Packets']}\n"
        tcppayload += f"{stats['Average Rx Bytes']}\n"
        tcppayload += f"{stats['Average Rx Errors']}\n"
        tcppayload += f"{stats['Average Tx Packets']}\n"
        tcppayload += f"{stats['Average Tx Bytes']}\n"
        tcppayload += f"{stats['Average Tx Errors']}\n"
        tcppayload += f"{stats['Average Rx Utilization']}\n"
        tcppayload += f"{stats['Average Tx Utilization']}\n"
        tcppayload += f"{stats['Average Throughput (Mbps)']}\n"
        tcppayload += f"{stats['Average Buffer Occupancy']}\n"
    # Add a checksum for the entire payload
    checksum = sum([ord(c) for c in tcppayload]) % 65536
    tcppayload += f"Checksum: {checksum}\n"
    tcppayload += "CC2DC ROUTER PACKET ENDED\n\n"

    return tcppayload

def craft_to_cc2dc_router_rules_protocol_payload(routerstats, CC_Name):
    """
    Craft the CC2DC protocol payload for router telemetry data.
    
    Format:
        CC2DC ROUTER PACKET STARTED
        <CC_Name>
        <Number of Router Devices> (8 bits)
        Time: YYYY-MM-DDTHH:mm:ss.SSS GMT
        For every Router:
            MAC: <MAC>
            Number of Routes: <data>
            Timestamp: <data>
            For every route:
                (The route details)
        Checksum: <16-bit checksum>
        CC2DC ROUTER PACKET ENDED
    """
    timenow = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    payload = "CC2DC ROUTER RULES PACKET STARTED\n"
    payload += f"{CC_Name}\n"
    payload += f"{len(routerstats)}\n"
    payload += f"{timenow} GMT\n"
    for mac, stats in routerstats.items():
        payload += f"{mac}\n"
        payload += f"{stats.get('Number of Routes', 'N/A')}\n"
        payload += f"{stats.get('Timestamp', 'N/A')}\n"
        routes = stats.get("Routes", [])
        for route in routes:
            payload += f"{route}\n"
    checksum = sum(ord(c) for c in payload) % 65536
    payload += f"Checksum: {checksum}\n"
    payload += "CC2DC ROUTER RULES PACKET ENDED\n\n"
    return payload

def craft_to_cc2dc_firewall_protocol_payload(fwstats, CC_Name):
    pass

def craft_to_cc2dc_firewall_rules_protocol_payload(fwrulestats, CC_Name):
    pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract switch statistics from a pcap file.")
    parser.add_argument("pcap_file", type=str, help="The path to the pcap file.")
    parser.add_argument("CC_Name", type=str, help="The name of the Control Center.")
    args = parser.parse_args()

    pcap_file_path = args.pcap_file
    CC_Name = args.CC_Name

    swstats = find_switch_packets_scapy(pcap_file_path)
    rtstats = find_router_packets_scapy(pcap_file_path)
    rtrstats = find_router_rules_packets_scapy(pcap_file_path)
    print(swstats)
    print(rtstats)

    tcp_payload_sw = craft_to_cc2dc_switch_protocol_payload(swstats, CC_Name)
    tcp_payload_rt = craft_to_cc2dc_router_protocol_payload(rtstats, CC_Name)
    tcp_payload_rtr = craft_to_cc2dc_router_rules_protocol_payload(rtrstats, CC_Name)
    # Save to a file cc1_payload.txt
    with open(f"{CC_Name.lower()}_payload.txt", "w") as f:
        f.write(tcp_payload_sw)
        f.write(tcp_payload_rt)
        f.write(tcp_payload_rtr)

    print(f"Payload saved to {CC_Name.lower()}_payload.txt")
