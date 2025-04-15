from scapy.all import rdpcap, Raw
import datetime
import argparse

# Read the file capture.pcap
def read_pcap(file_path):
    packets = rdpcap(file_path)
    return packets
# Split the data with newline or whitespaces
def split_data(data):
    return data.split()
# Append the data to an existing dc_data.csv
# If the file does not exist, create it


def append_to_csv(file_path, data):
    with open(file_path, 'a') as f:
        f.write(','.join(data) + '\n')
# Check if the file exists
def file_exists(file_path):
    try:
        with open(file_path, 'r'):
            return True
    except FileNotFoundError:
        return False
    
# Take filename input from commandline
def main():
    parser = argparse.ArgumentParser(description='Process pcap files.')
    parser.add_argument('filename', type=str, help='The name of the pcap file to process')
    args = parser.parse_args()
    
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
                print(f"Payload: {payload_str}")
                if "SOS" in payload_str:
                    print("SOS packet detected")
                    # Write it in csv file called dc_sos_data.csv
                    data = split_data(payload_str)
                    data_to_csv = data[4], data[7]
                    append_to_csv('dc_sos_data.csv', data_to_csv)
                    print(f"Data appended to dc_sos_data.csv: {data}")
                else:
                    # Split the data
                    data = split_data(payload_str)
                    # Append to csv file
                    append_to_csv('dc_data.csv', data)
                    print(f"Data appended to dc_data.csv: {data}")
            else:
                print("Payload is not Raw")
        else:
            print("Packet is not UDP")

if __name__ == '__main__':
    main()