import argparse
import pandas as pd
import csv
import os
import faiss
from utils.packet_parser import parse_csv
import pickle
from app import app

def is_convertible_to_float(series):
    try:
        series.astype(float)
        return True
    except ValueError:
        return False

def parse_csv_to_vectors(csv_file):
    pd.options.mode.chained_assignment = None

    dataframes = []
    with app.app_context():
        try:
            parsed_data = parse_csv(csv_file)
            df = pd.DataFrame(parsed_data)
            dataframes.append(df)
        except Exception as e:
            print(f"Error parsing {csv_file}: {e}")

    all_data = pd.concat(dataframes, ignore_index=True)
    all_data['Stats'] = all_data['Stats'].apply(lambda x: list(x.values())[0] if isinstance(x, dict) and len(x) > 0 else None)
    stats_data = pd.json_normalize(all_data['Stats'])
    all_data_flattened = pd.concat([all_data.drop(columns=['Stats']), stats_data], axis=1)

    numeric_columns = [col for col in all_data_flattened.columns if is_convertible_to_float(all_data_flattened[col])]
    numeric_data = all_data_flattened[numeric_columns]
    columns_to_keep = ['CC_Name']
    numeric_data[columns_to_keep] = all_data_flattened[columns_to_keep]

    columns_to_keep = ['CC_Name']
    numeric_data[columns_to_keep] = all_data_flattened[columns_to_keep]
    numeric_data = numeric_data.astype(float, errors='ignore')
    numeric_data = numeric_data.fillna(0)

    exclude_columns = ['CC_Name']
    grouped_data = numeric_data.groupby(['CC_Name'], as_index=False).mean(numeric_only=True)
    grouped_data[exclude_columns] = numeric_data[exclude_columns].drop_duplicates(subset=['CC_Name']).reset_index(drop=True)

    vals = None
    with open('../vectorDB/vals.pkl', 'rb') as file:
        vals = pickle.load(file)

    cc_ids = grouped_data['CC_Name'].values.tolist()
    grouped_data = grouped_data.drop(['CC_Name'], axis=1)

    vectors = grouped_data.values.astype('float32')
    return vectors, vals, cc_ids

def main():
    parser = argparse.ArgumentParser(description="Detect potential attack by finding nearest neighbors using FAISS.")
    parser.add_argument('--csv', required=True, help="Path to CSV file containing query vectors")
    args = parser.parse_args()

    query_vectors, vals, cc_ids = parse_csv_to_vectors(args.csv)
    num_queries, dimension = query_vectors.shape

    index = faiss.read_index('../vectorDB/keys.index')

    distances, indices = index.search(query_vectors, 5)

    file_exists = os.path.isfile("attack_log.csv")
    with open("attack_log.csv", "a", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        
        if not file_exists:
            csv_writer.writerow(["CC_Name", "Attack_Detected", "Attack_Type"])

        for i in range(num_queries):
            attack = False
            attack_type = ""
            cnil = 0
            for rank, (neighbor_index, distance) in enumerate(zip(indices[i], distances[i])):
                if vals[neighbor_index] == "nil":
                    cnil += 1
                else:
                    attack_type = vals[neighbor_index]
            
            if cnil < 3:
                attack = True

            if attack:
               csv_writer.writerow([cc_ids[i].upper(), "Yes", attack_type.upper()])
            else:
                csv_writer.writerow([cc_ids[i].upper(), "No", "None"])

if __name__ == '__main__':
    main()