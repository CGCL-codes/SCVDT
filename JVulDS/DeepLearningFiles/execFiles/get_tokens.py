# -*- coding:utf-8 -*-
"""
The python file is used to get tokens for every sentence.
"""
import re


identifier = '[^_a-zA-Z0-9$]'  # 除了这几类字符以外
space = '\s'  # 任意空白字符


# 字符匹配 失败返回false
def is_phor(pattern, param):
    m = re.search(pattern, param)
    if m is not None:
        return True
    return False


# 是否是双操作符
def is_doubleOperator(param, param1):
    # double = ('->', '--', '-=', '+=', '++', '>=', '<=', '==', '!=', '*=', '/=', '%=', '&=', '^=', '||', '&&', '>>',
    # '<<', '|=')  # 待补充？？？？？
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


# 三 操作符
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
        if is_phor(space, statement[i]):  # 是否是空格
            if i > j:
                words.append(statement[j:i])
                j = i + 1
            else:
                j = i + 1
        elif is_phor(identifier, statement[i]):  # 是否是标识符中的字符 不是的情况下
            if i + 1 < length and is_phor(identifier, statement[i+1]):
                if is_doubleOperator(statement[i], statement[i+1]):  # 双
                    doubleOperator = statement[i] + statement[i+1]
                    if i + 2 < length and is_phor(identifier, statement[i+2]):  # *** 第三位是什么 是非字符 数字 _ $ 时
                        if is_trOperator(doubleOperator, statement[i+2]): # 三个字符的操作符
                            words.append(statement[j:i])
                            words.append(doubleOperator + statement[i+2])
                            j = i + 3
                            i += 2
                        else:  # *** 第三位 空格或者其他
                            words.append(statement[j:i])
                            words.append(doubleOperator)
                            words.append(statement[i+2])
                            j = i + 3
                            i += 2
                    else:  # 前两位是操作符  第三位是 字符 数字 _ $
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
    # hj add:2021.3.10 加上最后一个单词
    if j < i:
        words.append(statement[j:i])

    count = 0
    count1 = 0
    sub0 = '\r'
    # 去除换行符
    if sub0 in words:
        words.remove('\r')
    # 去除空格
    for sub1 in words:
        if sub1 == ' ':
            count1 = count1 + 1

    for j in range(count1):
        words.remove(' ')

    for sub in words:  # 去除空字符
        if sub == '':
            count = count + 1

    for i in range(count):
        words.remove('')

    return words


