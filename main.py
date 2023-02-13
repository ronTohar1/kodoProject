from save_and_load import load_model
from utilities import *
import pefile
import psutil
from utilization import get_process_utilization
from create_csv import reload_features, get_file_row
import re
import floss

def get_process_prediction(process, model, features):
    try:
        process_path = process.exe()
        if process_path.endswith(".exe"):
            print("EXE ------", process.name()+ " path = ", process_path)
            row = get_file_row(str(process_path), features, 0)
            # remove row["label"]
            row = row.drop("label")
            print(row.to_frame().T)
            prediction = model.predict(row.to_frame().T)
            return prediction
        else:
            print("Not an exe file: ", process.name())
            return None
    except (psutil.AccessDenied, psutil.ZombieProcess, FileNotFoundError, pefile.PEFormatError):
        print("Access denied to process: " + process.name())
        return None


def main():
    model = load_model()
    features = reload_features()

    processes = psutil.process_iter()
    for process in processes:
        # utilization = get_process_utilization(process)
        row = get_process_prediction(process, model, features)
        if row is not None:
            print("Prediction: ", row)
            print("--------------------------------------------------")
if __name__ == "__main__":
    main()
