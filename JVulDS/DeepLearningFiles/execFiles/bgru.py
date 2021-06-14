"""
用作bgru模型的训练和测试
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

from keras.wrappers.scikit_learn import KerasClassifier
from sklearn.model_selection import GridSearchCV

from preprocess_dl_Input_version5 import *
import tensorflow as tf
import csv

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

    model.compile(loss='binary_crossentropy', optimizer='adamax',
                  metrics=[keras.metrics.FalsePositives(), keras.metrics.FalseNegatives(),
                           keras.metrics.BinaryAccuracy(), keras.metrics.Precision()])

    model.summary()

    return model


def main(traindataSetPath, weightPath, batchSize, maxlen, vector_dim, layers, dropout):
    print('loading data...')
    model = build_model(maxlen, vector_dim, layers, dropout)

    print('Train...')
    dataset = []
    labels = []
    for filename in os.listdir(traindataSetPath):
        if not filename.endswith('.pkl'):
            continue
        print(filename)
        f = open(os.path.join(traindataSetPath, filename), "rb")
        # if 'AE' in filename:
        # # dataset_file, labels_file, focous_sentences, funcs_file, filenames_file, testcases_file = pickle.load(f)  # 第三个参数没啥用
        # if filename.startswith("NVD25"):
        dataset_file, labels_file, focus_sentences_line, funcs_file, filenames_file, testcases_file = pickle.load(f)
        # else:
        #     dataset_file, labels_file, funcs_file, filenames_file, testcases_file = pickle.load(f)  # 第三个参数没啥用
        # else:
        #
        f.close()
        dataset += dataset_file
        labels += labels_file
    print("dataset length: ", len(dataset))
    print("labels length", len(labels))

    bin_labels = []
    for label in labels:
        bin_labels.append(multi_labels_to_two(label))
    labels = bin_labels

    np.random.seed(RANDOMSEED)
    np.random.shuffle(dataset)
    np.random.seed(RANDOMSEED)
    np.random.shuffle(labels)
    max = 0
    i = 0
    for sets in dataset:
        l = len(sets)
        if max < l:
            max = l
        if len(sets) > maxLen:
             dataset[i] = dataset[i][0:maxLen]
        i += 1
    print("  max list length:" + str(max))

    train_generator = generator_of_data(dataset, labels, batchSize, maxlen, vector_dim)
    all_train_samples = len(dataset)
    steps_epoch = int(all_train_samples / batchSize)
    print("samples number: %d" % all_train_samples)

    print("start")
    t1 = time.time()
    model.fit(train_generator, steps_per_epoch=steps_epoch, epochs=10)
    t2 = time.time()
    train_time = t2 - t1
    print(train_time)

    model.save_weights(weightPath)


if __name__ == "__main__":
    batchSize = 32
    vectorDim = 40
    maxLen = 800
    layers = 2
    dropout = 0.2

    traindataSetPath = "/Users/ke/Documents/snail/graduate/2_word2vec_Process/3_nvd/_4_24/all_input"
    weightPath = '/Users/ke/Documents/snail/graduate/2_word2vec_Process/3_nvd/_4_24/model_dl/model.h5'

    main(traindataSetPath, weightPath, batchSize, maxLen, vectorDim, layers, dropout)

