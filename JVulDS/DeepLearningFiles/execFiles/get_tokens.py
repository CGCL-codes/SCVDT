# -*- coding:utf-8 -*-
"""
The python file is used to get tokens for every sentence.
"""
import re


identifier = '[^_a-zA-Z0-9$]'  
space = '\s'  


def is_phor(pattern, param):
    m = re.search(pattern, param)
    if m is not None:
        return True
    return False


def is_doubleOperator(param, param1):
    # double = ('->', '--', '-=', '+=', '++', '>=', '<=', '==', '!=', '*=', '/=', '%=', '&=', '^=', '||', '&&', '>>',
    # '<<', '|=')  # 
    double = (
        '++', '--',
        '<<', '>>',
        '!=', '>=', '<=', '==',
        '-=', '+=', '/=', '*=', '%=', '|=', '^=',
        '&&', '||',
        '->'
    )
    string = param + param1
    if string in double:
        return True
    else:
        return False


# 
def is_trOperator(doubleOperator, param):
    three = ('>>=', '<<=', '>>>')
    if doubleOperator + param in three:
        return True
    return False


def get_tokens_list(sentence):
    i = 0
    j = 0
    statement = sentence
    length = len(sentence)
    words = []
    while i < length:
        # print("current character：" + statement[i])
        if is_phor(space, statement[i]): 
            if i > j:
                words.append(statement[j:i])
                j = i + 1
            else:
                j = i + 1
        elif is_phor(identifier, statement[i]):  
            if i + 1 < length and is_phor(identifier, statement[i+1]):
                if is_doubleOperator(statement[i], statement[i+1]):  
                    doubleOperator = statement[i] + statement[i+1]
                    if i + 2 < length and is_phor(identifier, statement[i+2]):  
                        if is_trOperator(doubleOperator, statement[i+2]): 
                            words.append(statement[j:i])
                            words.append(doubleOperator + statement[i+2])
                            j = i + 3
                            i += 2
                        else: 
                            words.append(statement[j:i])
                            words.append(doubleOperator)
                            words.append(statement[i+2])
                            j = i + 3
                            i += 2
                    else:  
                        words.append(statement[j:i])
                        words.append(doubleOperator)
                        j = i + 2
                        i += 1
                else:
                    words.append(statement[j:i])
                    words.append(statement[i])
                    words.append(statement[i+1])
                    j = i + 2
                    i += 1
            else:
                words.append(statement[j:i])
                words.append(statement[i])
                j = i + 1
        i += 1
    # hj add:2021.3.10 
    if j < i:
        words.append(statement[j:i])

    count = 0
    count1 = 0
    sub0 = '\r'
 
    if sub0 in words:
        words.remove('\r')

    for sub1 in words:
        if sub1 == ' ':
            count1 = count1 + 1

    for j in range(count1):
        words.remove(' ')

    for sub in words:  
        if sub == '':
            count = count + 1

    for i in range(count):
        words.remove('')

    return words


