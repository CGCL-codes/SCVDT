"""
测试模型
"""


import math
import pickle
import time

import keras
from keras.models import Sequential
# from tensorflow.python.keras import layers, models
from keras.layers.core import Masking, Dense, Dropout, Activation
from keras.layers.wrappers import Bidirectional
from keras.layers.recurrent import LSTM, GRU
import os
from preprocess_dl_Input_version5 import *
import tensorflow as tf


RANDOMSEED = 2018  # for reproducibility  TODO 干啥的
os.environ["CUDA_DEVICE_ORDER"] = "PCI_BUS_ID"
os.environ["CUDA_VISIBLE_DEVICES"] = "0"


# TODO 序贯模型
def build_model(maxlen, vector_dim, layers, dropout):
    print('Build model...')
    model = Sequential()
    model.add(Masking(mask_value=0.0, input_shape=(maxlen, vector_dim)))  # ？ 跳过某些层

    for i in range(1, layers):
        model.add(Bidirectional(
            GRU(units=256, activation='tanh', recurrent_activation='hard_sigmoid', return_sequences=True)))
        model.add(Dropout(dropout))

    model.add(Bidirectional(GRU(units=256, activation='tanh', recurrent_activation='hard_sigmoid')))
    model.add(Dropout(dropout))

    model.add(Dense(1, activation='sigmoid'))

    # model.compile(loss='binary_crossentropy', optimizer='adamax',
    #               metrics=['TP_count', 'FP_count', 'FN_count', 'precision', 'recall', 'fbeta_score'])

    # model.compile(loss='binary_crossentropy', optimizer='adamax', metrics=[
    #     tf.keras.metrics.TruePositives(),
    #     tf.keras.metrics.FalsePositives(),
    #     tf.keras.metrics.FalseNegatives(),
    #     tf.keras.metrics.Precision(),
    #     tf.keras.metrics.Recall()]
    #               )

    model.compile(loss='binary_crossentropy', optimizer='adamax', metrics=[keras.metrics.FalsePositives(), keras.metrics.FalseNegatives(), keras.metrics.BinaryAccuracy(),  keras.metrics.Precision()])

    model.summary()

    return model


def main(testdataSetPath, weightPath, resultpath, batchSize, maxLen, vectorDim,
         layers, dropout):
    model = build_model(maxLen, vectorDim, layers, dropout)
    model.load_weights(weightPath)
    print('Test......')
    dataset = []
    labels = []
    testcases = []
    filenames = []
    funcs = []
    slicename = []

    for filename in os.listdir(testdataSetPath):
        if not filename.endswith(".pkl"):
            continue
        print(filename)
        f = open(os.path.join(testdataSetPath, filename), "rb")
        # datasetfile, labelsfile, funcsfiles, filenamesfile, slicename_file = pickle.load(f)
        # if 'SE' in filename:
        datasetfile, labelsfile, focous_sentences, funcsfiles, filenamesfile, testcases_file = pickle.load(f)  # 第三个参数没啥用
        # datasetfile, labelsfile, funcsfiles, filenamesfile, slicename_file = pickle.load(f)  # 第三个参数没啥用
        # else:
        # datasetfile, labelsfile, funcsfiles, filenamesfile, slice = pickle.load(f)
        f.close()
        f.close()
        dataset += datasetfile
        labels += labelsfile

        funcs += funcsfiles
        filenames += filenamesfile

        # slicename += slicename_file
    # print(len(dataset), len(labels), len(testcases))
    print("all dataset: %d" % len(dataset))
    print("all labels: %d" % (len(labels)))
    all_test_samples = len(dataset)

    bin_labels = []
    for label in labels:
        bin_labels.append(multi_labels_to_two(label))
    labels = bin_labels

    i = 0
    max = 0
    for sets in dataset:
        l = len(sets)
        if max < l:
            max = l
        if len(sets) > maxLen:
            dataset[i] = dataset[i][0:maxLen]
        i += 1
    print(max)

    batch_size = 32
    test_generator = generator_of_data(dataset, labels, batch_size, maxLen, vectorDim)

    TP = 0
    TN = 0
    FP = 0
    FN = 0

    vuls_num = 0
    noVuls_num = 0

    TP_index = []
    results = {}
    dict_testcase2func = {}

    TP_slice_name = []

    t1 = time.time()

    FLAG_WRITE = False  # 模型输出序列写入文件的开关
    for i in range(math.floor(len(dataset) / batch_size)):
        print("\r", i, "/", math.floor(len(dataset) / batch_size), end="")
        # 测试输入
        test_input = next(test_generator)
        # 深度学习模型的序列输出
        layer_output = model.predict_on_batch([test_input[0]])
        # 测试结果
        for index in range(batch_size):
            y_pred = 1 if layer_output[index] >= 0.5 else 0

            if labels[i * batch_size + index] == 0:
                noVuls_num += 1
            else:
                vuls_num += 1
            # 漏洞分类的指标 & 漏洞分类的函数级指标 & 保存每个测试样本的序列输出
            # print(slicename)
            # currentslicename = slicename[i * batch_size + index].split(" ")[1].split("/")[0]
            # currentslicename = slicename[i * batch_size + index]
            # _filename = filenames[i * batch_size + index]
            #
            # print(currentslicename)
            if y_pred == 0 and labels[i * batch_size + index] == 0:
                TN += 1

            if y_pred == 0 and labels[i * batch_size + index] == 1:
                FN += 1

            if y_pred == 1 and labels[i * batch_size + index] == 0:
                FP += 1
                # if not currentslicename in dict_testcase2func.keys():
                #     dict_testcase2func[currentslicename] = {}

            if y_pred == 1 and labels[i * batch_size + index] == 1:
                TP += 1  # 正预测为正
                TP_index.append(i * batch_size + index)
                # if not currentslicename in TP_slice_name:
                #     TP_slice_name.append([currentslicename, _filename])
            results[slicename[i * batch_size + index]] = layer_output[index]

    # end = time.time()
    t2 = time.time()
    test_time = t2 - t1
    print("\nTest time cost: ", test_time)
    print("real vuls number: %d" % vuls_num)
    print("real no vuls number: %d" % noVuls_num)

    # 记录预测是正index
    with open(resultpath.replace(".txt", '') + "_TP_index.pkl", 'wb') as f:
        pickle.dump(TP_index, f)

    # 保存预测的漏洞行行号
    with open(resultpath.replace(".txt", '') + "_result.pkl", 'wb') as f:
        pickle.dump(results, f)

    # 保存testcase到函数的预测映射
    with open(resultpath.replace(".txt", '') + "_dict_testcase2func.pkl", 'wb') as f:
        pickle.dump(dict_testcase2func, f)

    with open(resultpath.replace(".txt", '') + "_TP_slicename.pkl", 'wb') as f:
        pickle.dump(TP_slice_name,f)

    # 记录实验结果 在result中
    with open(resultpath, 'a') as fwrite:
        # 实验基本信息
        fwrite.write('test_samples_num: {}\n'.format(len(dataset)))
        fwrite.write('test_dataset_path: {}\n'.format(testdataSetPath))
        fwrite.write('model path: {}\n'.format(weightPath))
        # 漏洞分类指标
        fwrite.write('TP: {}, FP:{}, FN:{}, TN:{}\n'.format(TP, FP, FN, TN))
        print('TP: {}, FP:{}, FN:{}, TN:{}\n'.format(TP, FP, FN, TN))
        FPR = FP / (FP + TN)
        fwrite.write('FPR: {}\n'.format(FPR))
        FNR = FN / (TP + FN)
        fwrite.write('FNR: {}\n'.format(FNR))
        accuracy = (TP + TN) / (len(dataset))
        fwrite.write('accuracy: {}\n'.format(accuracy))
        precision = TP / (TP + FP)
        fwrite.write('precision: {}\n'.format(precision))
        recall = TP / (TP + FN)
        fwrite.write('recall: {}\n'.format(recall))
        f_score = (2 * precision * recall) / (precision + recall)
        fwrite.write('fbeta_score: {}\n'.format(f_score))
        mcc = (TP * TN - FP * FN) / (math.sqrt((TP + FP) * (TP + FN) * (TN + FP) * (TN + FN)))
        fwrite.write('mcc: {}\n'.format(mcc))
        fwrite.write('--------------------\n')

    print("f1: ", f_score)


if __name__ == "__main__":
    batchSize = 32
    vectorDim = 40
    maxLen = 500
    layers = 2
    dropout = 0.2
    # traindataSetPath = "/Users/ke/Documents/snail/graduate/3_train/_s_train_pkl"
    testdataSetPath = "/Users/ke/Documents/snail/graduate/3_train/3_all/AE/test_input"
    # realtestdataSetPath = "data/"
    weightPath = "/Users/ke/Documents/snail/graduate/3_train/3_all/AE/model/model.h5" # 存放训练的模型
    resultPath = "/Users/ke/Documents/snail/graduate/platform/serverTest/Test/test_v2/result.txt"   # 存放训练的结果数据
    main(testdataSetPath, weightPath, resultPath, batchSize, maxLen, vectorDim,
         layers, dropout)

