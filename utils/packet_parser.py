import csv

def parse_custom_csv(filepath):
    with open(filepath, 'r') as file:
        rows = []
        for line in file:
            if 'PACKET,STARTED' in line:
                record = line.strip().split(',')
                if len(record) > 40:
                    rows.append({
                        "Latest Timestamp": record[5],
                        "Total Packets": int(record[12]),
                        # You can parse more fields here
                    })
        return rows
