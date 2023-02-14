from save_and_load import load_model
from utilities import *
import pefile
import psutil
from utilization import *
from create_csv import reload_features, get_file_row
import re
import floss

def get_process_prediction(process, model, features):
    try:
        process_path = process.exe()
        if process_path.endswith(".exe"):

            # print("EXE ------", process.name()+ " path = ", process_path)
            row = get_file_row(str(process_path), features, 0)
            # remove row["label"]
            row = row.drop("label")
            # print(row.to_frame().T)
            prediction = model.predict_proba(row.to_frame().T.values)
            return prediction[0] # Prediction probability for Not_miner, Miner labels
        else:
            # print("Not an exe file: ", process.name())
            return None
    except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError, pefile.PEFormatError):
        # print("Access denied to process: " + process.name())
        return None


def main():
    MODEL_IMPORTANCE = 0.70 # indicating of the importance of the static model prediction probability. (the dynamic analysing answer will count for 1 - MODEL_IMPORTANCE)
    model = load_model()
    features = reload_features()

    processes = psutil.process_iter()
    for process in processes:
        # utilization = get_process_utilization(process)
        pred = get_process_prediction(process, model, features)
        if pred is not None:
            utilization = get_dynamic_prediction(process)
            print(f"Prediction of {process.name()}:")
            print(" " * 10, "Static model prediction: ", pred)
            print(" " * 10, "Dynamic model prediction: ", utilization)
            final_prediction = (pred[0] * MODEL_IMPORTANCE) + (utilization * (1 - MODEL_IMPORTANCE))
            print(" " * 10, "Final prediction: ", final_prediction)
            if final_prediction > 0.5:
                print(" " * 10, "THIS PROCESS IS A MINER, WATCH OUT!")

if __name__ == "__main__":
    main()
