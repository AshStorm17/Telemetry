import argparse
import pandas as pd
import faiss
import os
from utils.packet_parser import parse_csv
import pickle
from app import app

def is_convertible_to_float(series):
    try:
        series.astype(float)
        return True
    except ValueError:
        return False

def parse_csv_to_vectors(dir_path):
    pd.options.mode.chained_assignment = None

    dataframes = []
    with app.app_context():
        for idx, file in enumerate(os.listdir(dir_path)):
            if file.endswith(".csv"):
                file_path = os.path.join(dir_path, file)
                attack_type = ''.join([char for char in file.split('.')[0] if not char.isdigit()])
                try:
                    parsed_data = parse_csv(file_path)
                    df = pd.DataFrame(parsed_data)
                    df['Filenumber'] = idx
                    df['Attack_Type'] = attack_type
                    dataframes.append(df)
                except Exception as e:
                    print(f"Error parsing {file_path}: {e}")

    all_data = pd.concat(dataframes, ignore_index=True)
    all_data['Stats'] = all_data['Stats'].apply(lambda x: list(x.values())[0] if isinstance(x, dict) and len(x) > 0 else None)
    stats_data = pd.json_normalize(all_data['Stats'])
    all_data_flattened = pd.concat([all_data.drop(columns=['Stats']), stats_data], axis=1)

    numeric_columns = [col for col in all_data_flattened.columns if is_convertible_to_float(all_data_flattened[col])]
    numeric_data = all_data_flattened[numeric_columns]
    columns_to_keep = ["Filenumber", 'CC_Name', 'Attack_Type']
    numeric_data[columns_to_keep] = all_data_flattened[columns_to_keep]

    columns_to_keep = ["Filenumber", 'CC_Name', 'Attack_Type']
    numeric_data[columns_to_keep] = all_data_flattened[columns_to_keep]
    numeric_data = numeric_data.astype(float, errors='ignore')
    numeric_data = numeric_data.fillna(0)

    numeric_data['Filenumber'] = numeric_data['Filenumber'].astype(int)
    exclude_columns = ['Filenumber', 'CC_Name', 'Attack_Type']
    grouped_data = numeric_data.groupby(['Filenumber', 'CC_Name', 'Attack_Type'], as_index=False).mean(numeric_only=True)

    grouped_data[exclude_columns] = numeric_data[exclude_columns].drop_duplicates(subset=['Filenumber', 'CC_Name', 'Attack_Type']).reset_index(drop=True)
    
    with open('vectorDB/vals.pkl', 'wb') as file:
        pickle.dump(grouped_data['Attack_Type'].values.tolist(), file)
    grouped_data = grouped_data.drop(['Filenumber', 'CC_Name', 'Attack_Type'], axis=1)

    vectors = grouped_data.values.astype('float32')
    return vectors


def main():
    parser = argparse.ArgumentParser(description="Initialize vector database using FAISS.")
    parser.add_argument('--dir', required=True, help="Path to directory containing CSV files")
    args = parser.parse_args()

    vectors = parse_csv_to_vectors(args.dir)
    num_vectors, dimension = vectors.shape
    print(f"Stored {num_vectors} vectors of dimension {dimension} in the vector DB")

    index = faiss.IndexFlatL2(dimension)
    index.add(vectors)

    faiss.write_index(index, 'vectorDB/keys.index')

if __name__ == '__main__':
    main()