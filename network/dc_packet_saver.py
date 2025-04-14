from scapy.all import rdpcap, Raw
import datetime
import argparse
import os

# Read the file capture.pcap
def read_pcap(file_path):
    packets = rdpcap(file_path)
    return packets

def split_telemetry_sections(content):
    """
    Splits the content into switch and router telemetry sections.
    
    Assumes the file contains:
      ... CC2DC PACKET STARTED
      ... (switch data)
      ... CC2DC ROUTER PACKET STARTED
      ... (router data)
      ... CC2DC PACKET ENDED
         or CC2DC ROUTER PACKET ENDED somewhere.
    
    Returns a tuple: (switch_section, router_section)
    """
    # Find the start indices of each section
    idx_switch_start = content.find("CC2DC PACKET STARTED")
    idx_router_start = content.find("CC2DC ROUTER PACKET STARTED")
    
    if idx_switch_start == -1:
        idx_switch_start = len(content)
    if idx_router_start == -1:
        idx_router_start = len(content)

    # The switch section is everything from the switch marker up to the router marker.
    switch_section = content[idx_switch_start:idx_router_start].strip()
    
    # Router section is from its marker up to the end marker for routers.
    # We attempt to find "CC2DC ROUTER PACKET ENDED". If not found, take to the end.
    idx_router_end = content.find("CC2DC ROUTER PACKET ENDED")
    if idx_router_end == -1:
        router_section = content[idx_router_start:].strip()
    else:
        # Include the router starting marker up to the router end marker.
        router_section = content[idx_router_start: idx_router_end + len("CC2DC ROUTER PACKET ENDED")].strip()
    
    return switch_section, router_section

def append_to_csv(file_path, data):
    with open(file_path, 'a') as f:
        f.write(','.join(data) + '\n')

def clean_section_lines(section, header_markers):
    """
    Given a telemetry section string, split it into lines and remove any header/footer markers.
    
    header_markers: list of strings that denote markers (e.g., "CC2DC PACKET STARTED", "CC2DC PACKET ENDED",
    "CC2DC ROUTER PACKET STARTED", "CC2DC ROUTER PACKET ENDED").
    
    Returns a list of nonempty lines that are not markers.
    """
    lines = section.splitlines()
    cleaned = [line.strip() for line in lines if line.strip() and not any(marker in line for marker in header_markers)]
    return '\n'.join(cleaned).split()

def main():
    parser = argparse.ArgumentParser(description='Process pcap files.')
    parser.add_argument('filename', type=str, help='The name of the pcap file to process')
    args = parser.parse_args()
    
    # Define markers to remove
    markers = [
        "CC2DC PACKET STARTED",
        "CC2DC PACKET ENDED",
        "CC2DC ROUTER PACKET STARTED",
        "CC2DC ROUTER PACKET ENDED"
    ]

    # Read the pcap file
    packets = read_pcap(args.filename)
    # Process each packet
    for packet in packets:
        # The packet is a UDP packet
        if packet.haslayer('UDP'):
            # Get the payload
            payload = packet['UDP'].payload
            # Check if the payload is Raw
            if isinstance(payload, Raw):
                # Decode the payload to string
                payload_str = payload.load.decode('ascii')
                # Split the data
                sw_data, rt_data = split_telemetry_sections(payload_str)
                sw_data = clean_section_lines(sw_data, markers)
                rt_data = clean_section_lines(rt_data, markers)
                # Append to csv file
                append_to_csv('dc_sw_data.csv', sw_data)
                append_to_csv('dc_rt_data.csv', rt_data)
                print(f"Data appended to dc_sw_data.csv: {sw_data}")
                print(f"Data appended to dc_rt_data.csv: {rt_data}")
            else:
                print("Payload is not Raw")
        else:
            print("Packet is not UDP")

if __name__ == "__main__":
    main()
