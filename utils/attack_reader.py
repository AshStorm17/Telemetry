import csv

def parse_attack_csv(filename):
    data = []
    with open(filename, 'r') as f:
        reader = csv.reader(f)
        headers = next(reader)  # Read the header row
        for row in reader:
            data.append({headers[i]: row[i] for i in range(len(headers))})
    return data

def main():
    # Example usage
    filename = '../network/attack_log.csv'
    data = parse_attack_csv(filename)
    for row in data:
        print(row)

if __name__ == "__main__":
    main()
