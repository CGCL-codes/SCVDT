import subprocess
import threading
import time

from get_slice import connect_neo4j, start
import sys
import os

from predictModel import predict
from process_slice import get_sentences
from train_w2vmodel import generate_w2vModel, get_input_dl, get_all_dl

"""
input: 
1）文件位置
2) 存放的固定文件的位置
"""

projPath = sys.argv[1]
slicePath = projPath + os.path.sep + "slice"
corpusPath = projPath + os.path.sep + "corpus"
vectorPath = projPath + os.path.sep + 'vector'
w2v_model_path = projPath + os.path.sep + 'w2v_model'
dlCorpusPath = projPath + os.path.sep + 'dlCorpus'
resultPath = projPath + os.path.sep + "result.txt"

fixFilePath = sys.argv[2]
w2v_input_path = fixFilePath + os.path.sep + "word2vec_input"

# step 1: 获取切片 得到slice
start(slicePath)
#
# step 2: 获取word2vec的输入 得到corpus
get_sentences(slicePath, corpusPath, mapType=True)

# # # step 3: 训练train_w2v并获取dl的输入 得到vector
dec_tokenFlaw_path = [corpusPath, w2v_input_path]
generate_w2vModel(dec_tokenFlaw_path, w2v_model_path)
get_input_dl(corpusPath, w2v_model_path, vectorPath)
get_all_dl(vectorPath, dlCorpusPath)
# #
# # step 4: 预测结果
predict(dlCorpusPath, fixFilePath + os.path.sep, resultPath)

