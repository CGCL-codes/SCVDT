import pickle
import sys
import os

from get_tokens import get_tokens_list
from mapping_v2 import mapping_v2, mapping_v3


def get_sentences(inputPath, corpusPath, mapType):
    for filename in os.listdir(inputPath):
        if not filename.endswith('.txt'):
            continue
        with open(os.path.join(inputPath, filename)) as f:
            sliceList = f.read()
            f.close()
        if len(sliceList) == 0:
            print("读取文件有误" + filename)
            continue
        sentences = sliceList.split('\n')
        if sentences[0] == '\r' or sentences[0] == '':
            del sentences[0]
        if not sentences:
            print("文件为空")
            continue
        if sentences[-1] == '':
            del sentences[-1]
        if sentences[-1] == '\r':
            del sentences[-1]
        if sentences[-1] != '0' and sentences[-1] != '1':
            print("文件没有标签" + inputPath)
            # sys.exit()
            continue
        label = int(sentences[-1])  # 标签

        # 解析第一行
        vul_dir_name = sentences[0].split(' ')[0]  # 第一个序号名
        vul_file_name = sentences[0].split(' ')[1]  # 第二个文件名
        focusLine = sentences[0].split(' ')[-1]

        sentences = sentences[1:len(sentences) - 1]

        # 最终存入pkl的内容
        sliceFile_focus = []  # focus的行号
        sliceFile_corpus = []  # 存储每个文件的语料库
        sliceFile_func = []  # 存储每一个slice的函数名
        sliceFile_label = []  # 存储label
        sliceFile_filename = []  # 存储文件名
        sliceFile_context = []

        sliceFile_focus.append(focusLine)  # 行号
        slice_corpus = []

        sliceFile_label.append(label)
        sliceFile_filename.append(vul_file_name)
        # print("1111")

        for sentence in sentences:
            # 先去后面的行号
            temp_list = sentence.split(" ")
            line_num = temp_list[-1]
            sentence_1 = ""
            for strs in temp_list[0:-1]:
                sentence_1 += strs + " "
            sentence = sentence_1.strip(" ")   # need test TODO
            if line_num == focusLine:
                sliceFile_context.append(sentence)
            # 删除注释 多行注释不可能 因为注释不会在节点上  删除在同一行的注释
            fm = str.find(sentence, '/*')
            if fm != -1:
                sentence = sentence[:fm]
            else:
                fm = str.find(sentence, '//')
                if fm != -1:
                    sentence = sentence[:fm]
            list_tokens = get_tokens_list(sentence)

            slice_corpus.append(list_tokens)  # 存储的是每一行的tokens

        # print(filename)
        if mapType:
            sentences2, slice_func = mapping_v3(slice_corpus)  # 对应变量和函数 benchmark
        else:
            sentences2, slice_func = mapping_v2(slice_corpus)  # 对应变量和函数 sard
        slice_funcs = filename[:-4].split("_")[-1]
        # print(slice_funcs)
        slice_func = list(set(slice_func))  # slice_func：切片中的函数  去除重复的函数
        if slice_func == []:
            slice_func = ['main']
        sample_corpus = []  # sample_corpus：分割切片成为一个整体的tokens
        for sentence in sentences2:  # sentence2是将变量名和函数替换之后的切片
            list_tokens = get_tokens_list(sentence)
            sample_corpus = sample_corpus + list_tokens  # 把每一个token转化为一个token存入sample_corpus中
        sliceFile_corpus.append(sample_corpus)  # slicefile_corpus：每一个切片的tokens  一个切片的tokens是一个list
        sliceFile_func.append(slice_funcs)

        folder_name = 'pos_' + filename[:-4]
        folder_path = os.path.join(corpusPath, folder_name)
        saveFilename = folder_path + '/' + filename[:-4] + '.pkl'
        if folder_name not in os.listdir(corpusPath):
            os.mkdir(folder_path)
        else:
            print("该文件夹已经存在")
            continue
        f1 = open(saveFilename, 'wb')
        # pickle：slicefile_corpus切片的tokens 标签 关注点的index（在tokens中的） 函数名 slicefile_filename的文件名
        if len(sliceFile_label) == 0 or sliceFile_label == []:
            print("标签是空: " + vul_dir_name)
            sys.exit()
        # print(sliceFile_corpus)
        pickle.dump([sliceFile_corpus, sliceFile_label, sliceFile_focus, sliceFile_func, sliceFile_filename, sliceFile_context],
                    f1)  # token序列 序列的label 关注点的行数  切片的函数 切片对应的.java文件名
        f1.close()


# slicePath = sys.argv[1]
# corpusPath = sys.argv[2]
# # print("slicePath %s" % slicePath)
# # print("corpus %s " % corpusPath)
#
# get_sentences(slicePath, corpusPath, mapType=True)