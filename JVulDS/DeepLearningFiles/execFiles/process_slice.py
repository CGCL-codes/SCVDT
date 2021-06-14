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
            print("read file error" + filename)
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
        label = int(sentences[-1])  


        vul_dir_name = sentences[0].split(' ')[0]  
        vul_file_name = sentences[0].split(' ')[1]  
        focusLine = sentences[0].split(' ')[-1]

        sentences = sentences[1:len(sentences) - 1]

        sliceFile_focus = []  
        sliceFile_corpus = []  
        sliceFile_func = []  
        sliceFile_label = []  
        sliceFile_filename = []  
        sliceFile_context = []

        sliceFile_focus.append(focusLine)  
        slice_corpus = []

        sliceFile_label.append(label)
        sliceFile_filename.append(vul_file_name)
        # print("1111")

        for sentence in sentences:
           
            temp_list = sentence.split(" ")
            line_num = temp_list[-1]
            sentence_1 = ""
            for strs in temp_list[0:-1]:
                sentence_1 += strs + " "
            sentence = sentence_1.strip(" ")   # need test TODO
            if line_num == focusLine:
                sliceFile_context.append(sentence)
         
            fm = str.find(sentence, '/*')
            if fm != -1:
                sentence = sentence[:fm]
            else:
                fm = str.find(sentence, '//')
                if fm != -1:
                    sentence = sentence[:fm]
            list_tokens = get_tokens_list(sentence)

            slice_corpus.append(list_tokens)  

        # print(filename)
        if mapType:
            sentences2, slice_func = mapping_v3(slice_corpus)  
        else:
            sentences2, slice_func = mapping_v2(slice_corpus)  
        slice_funcs = filename[:-4].split("_")[-1]
       
        slice_func = list(set(slice_func))  
        if slice_func == []:
            slice_func = ['main']
        sample_corpus = []  
        for sentence in sentences2:  
            list_tokens = get_tokens_list(sentence)
            sample_corpus = sample_corpus + list_tokens 
        sliceFile_corpus.append(sample_corpus) 
        sliceFile_func.append(slice_funcs)

        folder_name = 'pos_' + filename[:-4]
        folder_path = os.path.join(corpusPath, folder_name)
        saveFilename = folder_path + '/' + filename[:-4] + '.pkl'
        if folder_name not in os.listdir(corpusPath):
            os.mkdir(folder_path)
        else:
            print("file exists")
            continue
        f1 = open(saveFilename, 'wb')
        
        if len(sliceFile_label) == 0 or sliceFile_label == []:
            print("label is null: " + vul_dir_name)
            sys.exit()
        # print(sliceFile_corpus)
        pickle.dump([sliceFile_corpus, sliceFile_label, sliceFile_focus, sliceFile_func, sliceFile_filename, sliceFile_context],
                    f1)  
        f1.close()
