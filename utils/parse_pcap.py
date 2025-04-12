from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP

def parse_pcap_file(filepath):
    packets = rdpcap(filepath)
    data = []

    for pkt in packets:
        entry = {
            'timestamp': pkt.time,
            'size': len(pkt),
            'protocol': None,
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None
        }

        # Extract IP version and addresses
        if IP in pkt:
            entry['src_ip'] = pkt[IP].src
            entry['dst_ip'] = pkt[IP].dst
        elif IPv6 in pkt:
            entry['src_ip'] = pkt[IPv6].src
            entry['dst_ip'] = pkt[IPv6].dst

        # Extract transport protocol and ports
        if TCP in pkt:
            entry['protocol'] = 'TCP'
            entry['src_port'] = pkt[TCP].sport
            entry['dst_port'] = pkt[TCP].dport
        elif UDP in pkt:
            entry['protocol'] = 'UDP'
            entry['src_port'] = pkt[UDP].sport
            entry['dst_port'] = pkt[UDP].dport
        elif ICMP in pkt:
            entry['protocol'] = 'ICMP'

        data.append(entry)

    return data
