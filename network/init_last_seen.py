import sys
import csv
import datetime

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 init_last_seen.py <cluster_center_id> <mac1> [mac2] ...")
        sys.exit(1)

    cluster_center_id = sys.argv[1]
    mac_addresses = sys.argv[2:]

    creation_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    filename = f"{cluster_center_id}_SOS.csv"
    with open(filename, mode='w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["MAC", "last_seen"])
        for mac in mac_addresses:
            csvwriter.writerow([mac, creation_time])

if __name__ == "__main__":
    main()