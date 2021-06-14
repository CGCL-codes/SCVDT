import sys
import csv
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
    model.compile(loss='binary_crossentropy', optimizer='adamax', metrics=[keras.metrics.FalsePositives(), keras.metrics.FalseNegatives(), keras.metrics.BinaryAccuracy(),  keras.metrics.Precision()])
    model.summary()
    return model


def predict_type(testdataSetPath, weightPath, resultPath, batchSize, maxLen, vectorDim,
         layers, dropout, fwrite, types, result_list):
    dataset = []
    labels = []
    lines = []
    funcs = []
    filenames = []
    contexts = []
    slicenames = []

    model = build_model(maxLen, vectorDim, layers, dropout)
    model.load_weights(weightPath)

    for filename in os.listdir(testdataSetPath):
        if not filename.endswith(".pkl"):
            continue
        f = open(os.path.join(testdataSetPath, filename), "rb")
        datasetfile, labelsfile, linesfile, funcsfiles, filenamesfile, contextfiles, slicename_file = pickle.load(f)  # 第三个参数没啥用
        # datasetfile, labelsfile, linesfile, funcsfiles, filenamesfile = pickle.load(f)
        f.close()

        dataset += datasetfile
        labels += labelsfile
        lines += linesfile
        funcs += funcsfiles
        filenames += filenamesfile
        contexts += contextfiles
        slicenames += slicename_file

    # print(len(dataset))

    bin_labels = []
    for label in labels:
        bin_labels.append(multi_labels_to_two(label))
    labels = bin_labels

    i = 0
    for sets in dataset:
        l = len(sets)
        if len(sets) > maxLen:
            dataset[i] = dataset[i][0:maxLen]
        i += 1
    batch_size = len(dataset)
    test_generator = generator_of_data(dataset, labels, batch_size, maxLen, vectorDim)
    num = 0
    for i in range(math.floor(len(dataset) / batch_size)):
        print("\r", i, "/", math.floor(len(dataset) / batch_size), end="")
        # 测试输入
        test_input = next(test_generator)
        # 深度学习模型的序列输出
        layer_output = model.predict_on_batch([test_input[0]])
        # 测试结果
        for index in range(batch_size):
            y_pred = 1 if layer_output[index] >= 0.5 else 0
            if y_pred == 1:
                num += 1
            name = filenames[i * batch_size + index]
            line = lines[i * batch_size + index]
            context = contexts[i * batch_size + index]
            func = funcs[i * batch_size + index]
            slicename = slicenames[i * batch_size + index]
            category = slicename.split("_")[1]
            # print(category)
            if types == 0 and category == "AE":
                result_list.append([name, line, "Arithmetic expression", y_pred, func, context])
                fwrite.write('{}+{}+{}+{}+{}+{}\n'.format(name, line, category, y_pred, func, context))
            elif types == 1 and category == "MI":
                result_list.append([name, line, "Library/API function", y_pred, func, context])
                fwrite.write('{}+{}+{}+{}+{}+{}\n'.format(name, line, category, y_pred, func, context))
            elif types == 2 and category == "SE":
                result_list.append([name, line, "Sensitive exposure", y_pred, func, context])
                fwrite.write('{}+{}+{}+{}+{}+{}\n'.format(name, line, category, y_pred, func, context))
            # print(filenames[i * batch_size + index])
            # print(y_pred)
    # print("num: " + str(num))


def predict(vectorPath, fixFilePath, resultPath):
    batchSize = 32
    vectorDim = 40
    maxLen = 500
    layers = 2
    dropout = 0.2
    weightPath_AE = fixFilePath + 'dl_model' + os.path.sep + "AE" + os.path.sep + "model.h5"
    weightPath_MI = fixFilePath + 'dl_model' + os.path.sep + "MI" + os.path.sep + "model.h5"
    weightPath_SE = fixFilePath + 'dl_model' + os.path.sep + "SE" + os.path.sep + "model.h5"

    fwrite = open(resultPath, 'a')

    result_list = []
    predict_type(vectorPath, weightPath_AE, resultPath, batchSize, maxLen, vectorDim,
         layers, dropout, fwrite, 0, result_list)
    predict_type(vectorPath, weightPath_MI, resultPath, batchSize, 800, vectorDim,
               layers, dropout, fwrite, 1, result_list)
    predict_type(vectorPath, weightPath_SE, resultPath, batchSize, 800, vectorDim,
                 layers, dropout, fwrite, 2, result_list)
    fwrite.close()

    w = open(resultPath.replace(".txt", ".csv"), "w", newline="")
    write = csv.writer(w)
    for lists in result_list:
        write.writerow([lists[0], lists[1], lists[2], lists[3], lists[4], lists[5]])
    w.close()


# num = 0
# batchSize = 32
# vectorDim = 40
# maxLen = 800
# layers = 2
# dropout = 0.2
# testdataPath = "/Users/ke/Documents/snail/graduate/2_word2vec_Process/0_sard/_all/AE/vector"
#
# if __name__ == '__main__':
#     dlFilesPath = sys.argv[2]  # 固定文件的位置 为了得到模型的位置
#     predict()
#     print(num)


