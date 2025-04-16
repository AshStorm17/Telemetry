from scapy.all import rdpcap, Raw
import datetime
import argparse
import os

def read_pcap(file_path):
    packets = rdpcap(file_path)
    return packets

def split_telemetry_sections(content):
    idx_switch_start = content.find("CC2DC SWITCH PACKET STARTED")
    idx_router_start = content.find("CC2DC ROUTER PACKET STARTED")
    idx_router_rules_start = content.find("CC2DC ROUTER RULES PACKET STARTED")
    idx_firewall_start = content.find("CC2DC FIREWALL PACKET STARTED")
    idx_firewall_rules_start = content.find("CC2DC FIREWALL RULES PACKET STARTED")
    
    if idx_switch_start == -1:
        idx_switch_start = len(content)
    if idx_router_start == -1:
        idx_router_start = len(content)
    if idx_router_rules_start == -1:
        idx_router_rules_start = len(content)
    if idx_firewall_start == -1:
        idx_firewall_start = len(content)
    if idx_firewall_rules_start == -1:
        idx_firewall_rules_start = len(content)

    idx_switch_end = content.find("CC2DC SWITCH PACKET ENDED")
    idx_router_end = content.find("CC2DC ROUTER PACKET ENDED")
    idx_router_rules_end = content.find("CC2DC ROUTER RULES PACKET ENDED")
    idx_firewall_end = content.find("CC2DC FIREWALL PACKET ENDED")
    idx_firewall_rules_end = content.find("CC2DC FIREWALL RULES PACKET ENDED")

    if idx_switch_end == -1:
        idx_switch_end = len(content) - len("CC2DC SWITCH PACKET ENDED")
    if idx_router_end == -1:
        idx_router_end = len(content) - len("CC2DC ROUTER PACKET ENDED")
    if idx_router_rules_end == -1:
        idx_router_rules_end = len(content) - len("CC2DC ROUTER RULES PACKET ENDED")
    if idx_firewall_end == -1:
        idx_firewall_end = len(content) - len("CC2DC FIREWALL PACKET ENDED")
    if idx_firewall_rules_end == -1:
        idx_firewall_rules_end = len(content) - len("CC2DC FIREWALL RULES PACKET ENDED")
    
    switch_section = content[idx_switch_start:idx_switch_end + len("CC2DC SWITCH PACKET ENDED")].strip()
    router_section = content[idx_router_start:idx_router_end + len("CC2DC ROUTER PACKET ENDED")].strip()
    router_rules_section = content[idx_router_rules_start:idx_router_rules_end + len("CC2DC ROUTER RULES PACKET ENDED")].strip()
    firewall_section = content[idx_firewall_start:idx_firewall_end + len("CC2DC FIREWALL PACKET ENDED")].strip()
    firewall_rules_section = content[idx_firewall_rules_start:idx_firewall_rules_end + len("CC2DC FIREWALL RULES PACKET ENDED")].strip()
    
    return switch_section, router_section, router_rules_section, firewall_section, firewall_rules_section

def append_to_csv(file_path, data):
    with open(file_path, 'a') as f:
        f.write(','.join(data) + '\n')

def clean_section_lines(section, header_markers):
    lines = section.splitlines()
    cleaned = [line.strip() for line in lines if line.strip() and not any(marker in line for marker in header_markers)]
    return '\n'.join(cleaned).split()

def main():
    parser = argparse.ArgumentParser(description='Process pcap files.')
    parser.add_argument('filename', type=str, help='The name of the pcap file to process')
    args = parser.parse_args()
    
    markers = [
        "CC2DC SWITCH PACKET STARTED",
        "CC2DC SWITCH PACKET ENDED",
        "CC2DC ROUTER PACKET STARTED",
        "CC2DC ROUTER PACKET ENDED",
        "CC2DC ROUTER RULES PACKET STARTED",
        "CC2DC ROUTER RULES PACKET ENDED",
        "CC2DC FIREWALL PACKET STARTED",
        "CC2DC FIREWALL PACKET ENDED",
        "CC2DC FIREWALL RULES PACKET STARTED",
        "CC2DC FIREWALL RULES PACKET ENDED"
    ]

    packets = read_pcap(args.filename)

    for packet in packets:
        if packet.haslayer('UDP'):
            payload = packet['UDP'].payload
            if isinstance(payload, Raw):
                payload_str = payload.load.decode('ascii')
                sw_data, rt_data, rt_rules_data, fw_data, fw_rules_data = split_telemetry_sections(payload_str)
                sw_data = clean_section_lines(sw_data, markers)
                rt_data = clean_section_lines(rt_data, markers)
                rt_rules_data = clean_section_lines(rt_rules_data, markers)
                fw_data = clean_section_lines(fw_data, markers)
                fw_rules_data = clean_section_lines(fw_rules_data, markers)
                append_to_csv('dc_sw_data.csv', sw_data)
                append_to_csv('dc_rt_data.csv', rt_data)
                append_to_csv('dc_rt_rules_data.csv', rt_rules_data)
                append_to_csv('dc_fw_data.csv', fw_data)
                append_to_csv('dc_fw_rules_data.csv', fw_rules_data)
                append_to_csv('dc_data.csv', sw_data)
                append_to_csv('dc_data.csv', rt_data)
                append_to_csv('dc_data.csv', fw_data)
                print(f"Data appended to dc_sw_data.csv:\n{sw_data}")
                print(f"Data appended to dc_rt_data.csv:\n{rt_data}")
                print(f"Data appended to dc_rt_rules_data.csv:\n{rt_rules_data}")
                print(f"Data appended to dc_fw_data.csv:\n{fw_data}")
                print(f"Data appended to dc_fw_rules_data.csv:\n{fw_rules_data}")
            else:
                print("Payload is not Raw")
        else:
            print("Packet is not UDP")

if __name__ == "__main__":
    main()
