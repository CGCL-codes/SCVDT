# coding: utf-8
import os
import pickle
import argparse

def load_pickle(dpath):
    with open(dpath, 'rb') as f:
        data = pickle.load(f)  # 将文件中的数据解析为一个python对象
    return data


def load_data(data_dir):
    data_path = os.path.join(data_dir, 'data.p')
    # with open('data.p', 'rb') as f:
    #     data = pickle.load(f)  # 将文件中的数据解析为一个python对象
    data = load_pickle(data_path)
    (_new_frag_list, _new_frag_dict,
     _oov_pool, _type_dict) = data
    for frag in _new_frag_list:
        print(frag)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--data_dir', required=True)
    args = parser.parse_args()
    load_data(args.data_dir)
