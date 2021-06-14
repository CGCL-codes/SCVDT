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
1）filePath
2) own filePath
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

# step 1:get slice
start(slicePath)
#
# step 2: get the input of word2vec and get corpus
get_sentences(slicePath, corpusPath, mapType=True)

# # # step 3: get vector
dec_tokenFlaw_path = [corpusPath, w2v_input_path]
generate_w2vModel(dec_tokenFlaw_path, w2v_model_path)
get_input_dl(corpusPath, w2v_model_path, vectorPath)
get_all_dl(vectorPath, dlCorpusPath)
# #predict result
predict(dlCorpusPath, fixFilePath + os.path.sep, resultPath)

