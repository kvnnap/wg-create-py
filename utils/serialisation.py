import json

def load(file_name):
    with open(file_name, 'r') as fp:
        return json.load(fp)
    
