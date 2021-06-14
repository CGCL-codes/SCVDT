## Environment
neo4j-chs-community-3.5.19-unix, python 3.8.2, py2neo 2021.0.1, keras 2.4.3, gensim 3.8.3
```
# cmd
$ sudo pip3 install gensim
$ sudo pip3 install py2neo==2021.0.1
$ sudo pip3 install keras
```
## Description
**1. dl_model**

models of deep learning.

**2. execFiles**

(1) detectVul.py: use args as input, the result.csv as output.

(2) get_slice.py: generate slices of every vulnerability type to slice directory, you need modify password of Neo4j password.

(3) process_slice.py：generate the input of word2vec to corpus directory.

(4) train_w2vmodel.py: train word2vec model, get the input of deep learning to vector directory.

(5) predictModel.py: predict result to "result.csv".

(6) bgru.py: use train dataset to train bgru model.
 
(7) testModel.py: use test dataaset to predict model.

**3. softwareTempFiles**

the intermediate files for deep learning and the result of detecting vulnerablities.

**4. word2vec_input**

the input files for cross training of word2vec.
