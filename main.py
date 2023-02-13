from save_and_load import load_model
from utilities import *
from utilities import *
import pefile
import psutil
from utilization import get_process_utilization
from create_csv import reload_features, get_file_row

def get_process_prediction(process, model, features):
    process_path = process.exe()
    if process_path.endswith(".exe"):
        row = get_file_row(process_path, features, 0)
        print(row.to_frame())
        # prediction = model.predict(row.to_frame().T)
        # return prediction
    return None
def main():
    model = load_model()
    features = reload_features()

    processes = psutil.process_iter()
    for process in processes:
        # utilization = get_process_utilization(process)
        row = get_row_from_process(process)

