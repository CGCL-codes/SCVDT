import os

def get_file(path, file_type):
    file_list = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if os.path.splitext(file)[1] == file_type:
                file = os.path.splitext(file)[0]
                file_list.append(os.path.join(root, file))
    return file_list

def remove_file(file_list):
    for file_name in file_list:
        file = file_name + '.gcda'
        if not os.path.exists(file):
            continue
        os.remove(file)