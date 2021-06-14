# -*- coding:utf-8 -*-
"""
This python file is used to tranfer the words in corpus to vector, and save the word2vec model under the path 'w2v_model'.
"""

from gensim.models.word2vec import Word2Vec

import pickle
import os
import gc
import sys
"""
DirofCorpus class
-----------------------------
This class is used to make a generator to produce sentence for word2vec training

# Arguments
    dirname: The src of corpus files 

"""


class DirofCorpus(object):
    def __init__(self, dirname):
        self.dirname = dirname

    def __iter__(self):
        for d in self.dirname:
            for fn in os.listdir(d):
                # print(fn)
                if not os.path.isdir(d + '/' + fn):
                    continue
                for filename in os.listdir(os.path.join(d, fn)):
                    if not filename.endswith('.pkl'):
                        continue
                    samples = pickle.load(open(os.path.join(d, fn, filename), 'rb'))[0]
                    for sample in samples:
                        yield sample
                    del samples
                    gc.collect()


'''
generate_w2vmodel function
-----------------------------
This function is used to learning vectors from corpus, and save the model

# Arguments
    decTokenFlawPath: String type, the src of corpus file 
    w2vModelPath: String type, the src of model file 

'''


def generate_w2vModel(decTokenFlawPath, w2vModelPath):
    print("training...")
    model = Word2Vec(sentences=DirofCorpus(decTokenFlawPath), size=30, alpha=0.01, window=5, min_count=0,
                     max_vocab_size=None, sample=0.001, seed=1, workers=1, min_alpha=0.0001, sg=1, hs=0, negative=10,
                     iter=5)  # min_count was 0 when this program was downloaded from github
    model.save(w2vModelPath)


def generate_corpus_v2(w2vModelPath, samples):
    model = Word2Vec.load(w2vModelPath)
    print("begin generate input...")
    dl_corpus = [[model[word] for word in sample] for sample in samples]
    print("generate input success...")

    return dl_corpus


def get_input_dl(corpusPath, w2v_model_path, vectorPath):
    for corpusFiles in os.listdir(corpusPath):
        # print(corpusFiles)
        if not os.path.isdir(corpusPath + os.path.sep + corpusFiles):
            continue
        if corpusFiles not in os.listdir(vectorPath):
            folder_path = os.path.join(vectorPath, corpusFiles)
            if not os.path.exists(folder_path):
                os.mkdir(folder_path)
        for corpusFile in os.listdir(corpusPath + os.path.sep + corpusFiles):
            corpus_path = os.path.join(corpusPath, corpusFiles, corpusFile)
            f_corpus = open(corpus_path, 'rb')
            data = pickle.load(f_corpus)
            f_corpus.close()
            data[0] = generate_corpus_v2(w2v_model_path, data[0])  # 转化为向量
            vector_path = os.path.join(vectorPath, corpusFiles, corpusFile)
            f_vector = open(vector_path, 'wb')
            pickle.dump(data, f_vector, protocol=pickle.HIGHEST_PROTOCOL)
            f_vector.close()


def get_all_dl(vectorPath, dlCorpusPath):
    N = 1
    num = 1
    test_set = [[], [], [], [], [], [], []]
    for i in range(num):
        for folder in os.listdir(vectorPath):
            if not os.path.isdir(vectorPath + os.path.sep + folder):
                continue
            for filename in os.listdir(vectorPath + os.path.sep + folder):
                print(filename)
                if not filename.endswith(".pkl"):
                    continue
                f = open(vectorPath + os.path.sep + folder + os.path.sep + filename, 'rb')
                data = pickle.load(f)
                for n in range(6):
                    test_set[n] = test_set[n] + data[n]
                test_set[-1].append(filename)
        if test_set[0] == []:
            continue
        f_train = open(dlCorpusPath + os.path.sep + "test.pkl", "wb")
        pickle.dump(test_set, f_train, protocol=pickle.HIGHEST_PROTOCOL)
        f_train.close()
        del test_set
        gc.collect()
# argv[1]: 待检测文件夹路径
# argv[2]: 已经准备好的corpus

# basePath = sys.argv[1]
# dec_tokenFlaw_path = [basePath + os.path.sep + 'corpus', sys.argv[2]]
# w2v_model_path = basePath + os.path.sep + 'model'
# print(dec_tokenFlaw_path)
# print(w2v_model_path)
# generate_w2vModel(dec_tokenFlaw_path, w2v_model_path)
#
# corpusPath = basePath + os.path.sep + 'corpus'
# vectorPath = basePath + os.path.sep + 'vector'
# print(corpusPath)
# print(vectorPath)
# if __name__ == '__main__':
#     corpusPath = "/Users/ke/Documents/snail/graduate/platform/serverTest/Test/test_v2/corpus"
#     vectorPath = "/Users/ke/Documents/snail/graduate/platform/serverTest/Test/test_v2/vector"
#     w2v_model_path = "/Users/ke/Documents/snail/graduate/platform/serverTest/Test_v2/test/model"
#     get_input_dl(corpusPath, w2v_model_path, vectorPath)
#     dl_path = "/Users/ke/Documents/snail/graduate/platform/serverTest/Test/test/dlCorpus"
#     get_all_dl(vectorPath, dl_path)


