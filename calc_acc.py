import pandas as pd
import faiss
import os
from utils.packet_parser import parse_csv
from app import app
import numpy as np

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
    
    vals = grouped_data['Attack_Type'].values.tolist()
    grouped_data = grouped_data.drop(['Filenumber', 'CC_Name', 'Attack_Type'], axis=1)

    vectors = grouped_data.values.astype('float32')
    return vectors, vals

def shuffle(arrs):
    for arr in arrs:
        state = np.random.RandomState(0)
        state.shuffle(arr)

vectors, vals = parse_csv_to_vectors("attack")
shuffle([vectors, vals])

train_len = int(len(vectors)*0.9)

train_vectors = vectors[:train_len]
train_vals = vals[:train_len]

test_vectors = vectors[train_len:]
test_vals = vals[train_len:]

dimension = len(train_vectors[0])

index = faiss.IndexFlatL2(dimension)
index.add(train_vectors)
distances, indices = index.search(test_vectors, 5)

tp = fp = tn = fn = 0
for i in range(len(test_vectors)):
    attack = False
    attack_type = []
    cnil = 0
    for rank, (neighbor_index, distance) in enumerate(zip(indices[i], distances[i])):
        if train_vals[neighbor_index] == "nil":
            cnil += 1
        else:
            if len(attack_type) == 0:
                attack_type.append(train_vals[neighbor_index])
            else:
                if attack_type[-1] != train_vals[neighbor_index]:
                    attack_type.pop()
                else:
                    attack_type.append(train_vals[neighbor_index])
    if cnil < 3:
        attack = True
    if attack:
        act_attack = "syn"
        if len(attack_type) > 0:
            act_attack = attack_type[-1]
        if test_vals[i] != 'nil':
            tp += 1
        else:
            fp += 1
#        print(f"pred: {act_attack}, actual: {test_vals[i]}")
    else:
        if test_vals[i] == 'nil':
            tn += 1
        else:
            fn += 1
#        print(f"pred: nil, actual: {test_vals[i]}")

prec = (tp/(tp+fp))*100
recall = (tp/(tp+fn))*100
f1 = 2*prec*recall/(prec+recall)
print("Attack Detection Statistics")
print("---------------------------")
print(f"Accuracy: {((tp+tn)/(tp+tn+fp+fn))*100:.2f}%")
print(f"Precision: {prec:.2f}%")
print(f"Recall: {recall:.2f}%")
print(f"F1-Score: {f1:.2f}%")