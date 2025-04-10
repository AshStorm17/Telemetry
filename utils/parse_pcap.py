from scapy.all import rdpcap

def parse_pcap_file(filepath):
    packets = rdpcap(filepath)
    data = []

    for pkt in packets:
        if hasattr(pkt, 'time'):
            entry = {
                'timestamp': pkt.time,
                'size': len(pkt)
                # Add other fields like src/dst IP, port, protocol if needed
            }
            data.append(entry)
    
    return data  # List of dicts
