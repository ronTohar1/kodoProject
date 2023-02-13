from save_and_load import load_dataset, load_model, save_model

data = load_dataset()
# shuffle data and remove 50 percent of the data
data = data.sample(frac=1).reset_index(drop=True)
data = data.iloc[:int(len(data)), :]


X = data.iloc[:, :-1].values
y = data.iloc[:, -1].values

# print(data)
# print(data.iloc[:, -1])
# print(X)
# print(y)