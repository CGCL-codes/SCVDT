# -*- coding:utf-8 -*-
"""
该python文件将函数名和变量名用统一的名称代替
"""
import copy
import re
import xlrd

space = '\s'
identifier = '[^_a-zA-Z0-9$]'  # 非标识符 关键字
function = '^[_a-zA-Z\$][_a-zA-Z0-9\$]*$'  # 标识符  $ 怎么加进去
variable = '^[_a-zA-Z][_a-zA-Z0-9\$(\.)?]*$'
number = '[0-9]+'
stringConst = '(^\'[\s|\S]*\'$)|(^"[\s|\S]*"$)'


constValue = ['null', 'false', 'true']
# 关键字 不带括号
keywords = ('public', 'default', 'private', 'protected', 'implement', 'extends', 'interface', 'class', 'package',
            'boolean', 'short', 'int', 'long', 'float', 'double', 'byte', 'char', 'String', 'Object',
            'abstract', 'void', 'strcftp', 'native',
            'this', 'super',
            'do', 'case',
            'throw', 'throws', 'try', 'finally',
            'break', 'continue', 'goto', 'return',
            'import',
            'else',
            'instanceof',
            'transient', 'final', 'static', 'volatile', 'const', 'synchronized',
            'new',
            'struct', 'union', 'enum',
            'Throwable'
            )
keywords_1 = ('catch', 'if', 'while', 'for', 'switch', 'synchronized')
keywords_2 = ('readLine', 'trim', 'close', 'add', 'remove', 'put', 'get', 'writeObject', 'toByteArray', 'readObject',
              'nextInt', 'openConnection', 'getInputStream', 'load', 'getProperty', 'accept', 'getQueryString',
              'hasMoreTokens', 'nextToken', 'startsWith', 'substring', 'getParameter', 'getCookies', 'getValue',
              'toUpperCase', 'getCanonicalName', 'putIfAbsent', 'setAccessible', 'computeIfAbsent', 'getFile',
              'defaultReadObject', 'delete', 'hasNext', 'next', 'copy', 'contains', 'setAttribute', 'encode',
              'getHeader', 'abs', 'write', 'getByteBuffer', 'closeEntry', 'method', 'addHeaders', 'append', 'trim',
              'getLoader', 'getClassLoader', 'newInstance', 'indexOf'
              )
keywords_3 = ('System.out.print*', 'print*')   # 模糊匹配类型
keywords_4 = []  # 需要补充之处 存于excel
# TODO
xread = xlrd.open_workbook('function.xls')
for sheet in xread.sheets():
    col = sheet.col_values(0)[1:]
    keywords_4 += col

keywords_5 = [] # 机动组
keywords_6 = ['IO', 'Vector', 'Byte', 'LinkedList', 'HashMap', 'Integer', 'byte', 'short', 'Short', 'nextLong', 'long',
              'Long', 'int', 'Integer', 'String', 'IOException', 'XMLConstants', 'T', 'boolean', 'Boolean', 'char',
              'Char', 'length', 'object', 'Object', 'this', 'Class']


keywords_7 = []   # 主要是.部分的过滤
# TODO
xread = xlrd.open_workbook('function1.xls')
for sheet in xread.sheets():
    col = sheet.col_values(0)[1:]
    keywords_7 += col


# 是否是空格
def is_phor(pattern, param):
    m = re.search(pattern, param)
    if m is not None:
        return True
    return False


def var(param):  # 识别标识符
    m = re.match(function, param)  # re.match只匹配字符串的开始
    if m is not None:
        return True
    else:
        return False


def createVariable(string, token):
    length = len(string)
    stack1 = []
    s = ''
    i = 0
    while i < length:
        # print(string[i])
        if var(string[i]):
            while stack1:
                s = stack1.pop() + s
            s = s + string[i]
            token.append(s)
            s = ''
            i = i + 1
        else:
            token.append(string[i])
            i = i + 1


def isInKeyword_3(param):
    for key in keywords_3:
        if len(param) < len(key)-1:
            return False
        if key[:-1] == param[:len(key)-1]:
            return True
        else:
            return False


def mapping_v2(list_sentence):
    list_code = []
    list_func = []
    for code in list_sentence:
        # print(code)
        _string = ''
        for c in code:
            _string = _string + ' ' + c
        _string = _string[1:]
        list_code.append(_string)

    # print(list_code)
    index = 0
    _func_dict = {}
    _variable_dict = {}
    while index < len(list_code):
        string = []
        token = []
        str1 = copy.copy(list_code[index])  # 存储一行代码: byte data;
        i = 0
        j = 0
        tag = 0  # 字符串
        strtemp = ''
        while i < len(str1):  # str1 : byte data
            if tag == 0:
                if is_phor(space, str1[i]):  # 空格
                    if i > 0:
                        string.append(str1[j:i])
                        j = i + 1
                    else:
                        j = i + 1
                    i += 1

                elif i == len(str1)-1:       # 最后一个字符
                    string.append(str1[j:i + 1])
                    break

                elif is_phor(identifier, str1[i]):  # 懒得改了...
                    if i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '>':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '<' and str1[i + 1] == '<':
                        if i + 2 < len(str1) and str1[i + 2] == '=':
                            string.append(str1[i] + str1[i+1] + str1[i+2])
                            j = i + 3
                            i = i + 3
                        else:
                            string.append(str1[i] + str1[i + 1])
                            j = i + 2
                            i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '>' and str1[i + 1] == '>':
                        if i + 2 < len(str1) and (str1[i + 2] == '=' or str1[i + 2] == '>'):
                            string.append(str1[i] + str1[i + 1] + str1[i + 2])
                            j = i + 3
                            i = i + 3
                        else:
                            string.append(str1[i] + str1[i + 1])
                            j = i + 2
                            i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '&' and str1[i + 1] == '&':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '|' and str1[i + 1] == '|':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '|' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2
                    elif i + 1 < len(str1) and str1[i] == '=' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '!' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '+' and str1[i + 1] == '+':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '-':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '+' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif str1[i] == '"':
                        strtemp = strtemp + str1[i]
                        i += 1
                        tag = 1  # 字符串

                    elif str1[i] == '\'':
                        strtemp = strtemp + str1[i]
                        i += 1
                        tag = 2

                    else:
                        string.append(str1[i])
                        j = i + 1
                        i += 1
                else:  # 是标识符
                    i += 1
            elif tag == 1:
                if str1[i] != '"':
                    strtemp = strtemp + str1[i]
                    i = i + 1
                else:
                    strtemp = strtemp + str1[i]
                    string.append(strtemp)
                    strtemp = ''
                    tag = 0
                    j = i + 1
                    i += 1
            elif tag == 2:
                if str1[i] != '\'':
                    strtemp = strtemp + str1[i]
                    i = i + 1
                else:
                    strtemp = strtemp + str1[i]
                    string.append(strtemp)
                    strtemp = ''
                    tag = 0
                    j = i + 1
                    i += 1
        count = 0
        for sub in string:
            if sub == '':
                count += 1

        for i in range(count):
            string.remove('')

        createVariable(string, token) # 啥也没干？？？
        # print(token)
        # mapping function and variable
        j = 0
        while j < len(token):
            word = token[j]
            if word in constValue:  # 字面量
                j += 1
            elif j < len(token) and is_phor(variable, word):
                if word in keywords:
                    j += 1
                # new
                elif j - 1 >= 0 and j + 1 < len(token) and token[j - 1] == 'new' and token[j + 1] == '[':
                    j += 2
                elif j + 1 < len(token) and token[j + 1] == '(':  # 后面是( 则证明可能是方法
                    # print(token[j])
                    if index == 0:
                        list_func.append(word)
                    if word in keywords_1:
                        j = j + 2
                    elif word in keywords_2:  # keywords_2 应该是函数的调用 TODO 需要增加
                        j = j + 2
                    elif isInKeyword_3(token[j]):  # keywords_3 模糊匹配 TODO 需要增加
                        j = j + 2
                    elif word in keywords_4:  # TODO
                        j = j + 2
                    elif word in keywords_5:  # 机动组
                        j = j + 2

                    else:
                        if 'good' in word or 'bad' in word:  # SARD中的函数特有的标志
                            # print(token[j])
                            list_func.append(str(word))
                        if token[j] in _func_dict.keys():  # 已存入  key:old value:new
                            token[j] = _func_dict[token[j]]  # word -> 转化之后的
                            j += 2
                        else:
                            if 'good' not in word and 'bad' not in word and 'privateReturns' not in word:
                                j = j + 2
                                continue
                            list_values = _func_dict.values()
                            if len(list_values) == 0:
                                _func_dict[token[j]] = 'func_0'
                                token[j] = _func_dict[token[j]]
                            else:
                                if token[j] in _func_dict.keys():
                                    token[j] = _func_dict[token[j]]
                                else:
                                    list_num = []
                                    for value in list_values:
                                        list_num.append(int(value.split('_')[-1]))
                                    _max = max(list_num)
                                    _func_dict[token[j]] = 'func_' + str(_max + 1)
                                    token[j] = _func_dict[token[j]]
                            j = j + 2
                # variable
                elif j + 1 < len(token) and (not is_phor(variable, token[j + 1])):
                    if word in _variable_dict.keys():
                        token[j] = _variable_dict[token[j]]
                        j += 2
                        continue
                    elif token[j+1] == '.':        # 处理.的情况 可能需要改正
                        token1 = token[j+2:]
                        str2 = word + '.'
                        m = j + 2
                        for t in token1:
                            if t != '.' and not is_phor(function, t):
                                break
                            if is_phor(function, t) and token[m - 1] != '.':  # 后面是空格
                                break
                            str2 = str2 + t
                            m += 1
                        if str2 in keywords_4 or 'A' <= str2[0] <= 'Z' or str2 in keywords_7:
                            j = m
                            continue
                    if word in keywords_6 or word in keywords_7:
                        j += 2
                        continue
                    else:
                        list_values = _variable_dict.values()
                        if len(list_values) == 0:
                            _variable_dict[token[j]] = 'variable_0'
                            token[j] = _variable_dict[token[j]]

                        else:
                            if token[j] in _variable_dict.keys():
                                token[j] = _variable_dict[token[j]]
                            else:
                                list_num = []
                                for value in list_values:
                                    list_num.append(int(value.split('_')[-1]))

                                _max = max(list_num)
                                _variable_dict[token[j]] = 'variable_' + str(_max + 1)
                                token[j] = _variable_dict[token[j]]
                        j = j + 2
                # last token
                elif j + 1 == len(token):
                    list_values = _variable_dict.values()
                    if len(list_values) == 0:
                        _variable_dict[token[j]] = 'variable_0'
                        token[j] = _variable_dict[token[j]]

                    else:
                        if token[j] in _variable_dict.keys():
                            token[j] = _variable_dict[token[j]]
                        else:
                            list_num = []
                            for value in list_values:
                                list_num.append(int(value.split('_')[-1]))

                            _max = max(list_num)
                            _variable_dict[token[j]] = 'variable_' + str(_max + 1)
                            token[j] = _variable_dict[token[j]]
                        break
                else:
                    j += 1
            elif j < len(token) and is_phor(number, word):
                j += 1
            elif j < len(token) and is_phor(stringConst, word):
                j += 1
            else:
                j += 1
        temp = ''
        i = 0
        while i < len(token):
            if i == len(token) - 1:
                temp = temp + token[i]
            else:
                temp = temp + token[i] + ' '
            i += 1

        list_code[index] = temp  # 转化为fun variable之后的字符串的形式
        index += 1
        # print(temp)

    return list_code, list_func


# 因为需要改一些
def mapping_v3(list_sentence):
    list_code = []
    list_func = []
    for code in list_sentence:
        # print(code)
        _string = ''
        for c in code:
            _string = _string + ' ' + c
        _string = _string[1:]
        list_code.append(_string)

    # print(list_code)
    index = 0
    _func_dict = {}
    _variable_dict = {}
    while index < len(list_code):
        string = []
        token = []
        str1 = copy.copy(list_code[index])  # 存储一行代码: byte data;
        i = 0
        j = 0
        tag = 0  # 字符串
        strtemp = ''
        while i < len(str1):  # str1 : byte data
            if tag == 0:
                if is_phor(space, str1[i]):  # 空格
                    if i > 0:
                        string.append(str1[j:i])
                        j = i + 1
                    else:
                        j = i + 1
                    i += 1

                elif i == len(str1) - 1:  # 最后一个字符
                    string.append(str1[j:i + 1])
                    break

                elif is_phor(identifier, str1[i]):  # 懒得改了...
                    if i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '>':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '<' and str1[i + 1] == '<':
                        if i + 2 < len(str1) and str1[i + 2] == '=':
                            string.append(str1[i] + str1[i + 1] + str1[i + 2])
                            j = i + 3
                            i = i + 3
                        else:
                            string.append(str1[i] + str1[i + 1])
                            j = i + 2
                            i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '>' and str1[i + 1] == '>':
                        if i + 2 < len(str1) and (str1[i + 2] == '=' or str1[i + 2] == '>'):
                            string.append(str1[i] + str1[i + 1] + str1[i + 2])
                            j = i + 3
                            i = i + 3
                        else:
                            string.append(str1[i] + str1[i + 1])
                            j = i + 2
                            i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '&' and str1[i + 1] == '&':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '|' and str1[i + 1] == '|':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '|' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '=' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '!' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '+' and str1[i + 1] == '+':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '-':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '+' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif i + 1 < len(str1) and str1[i] == '-' and str1[i + 1] == '=':
                        string.append(str1[i] + str1[i + 1])
                        j = i + 2
                        i = i + 2

                    elif str1[i] == '"':
                        strtemp = strtemp + str1[i]
                        i += 1
                        tag = 1  # 字符串

                    elif str1[i] == '\'':
                        strtemp = strtemp + str1[i]
                        i += 1
                        tag = 2

                    else:
                        string.append(str1[i])
                        j = i + 1
                        i += 1
                else:  # 是标识符
                    i += 1
            elif tag == 1:
                if str1[i] != '"':
                    strtemp = strtemp + str1[i]
                    i = i + 1
                else:
                    strtemp = strtemp + str1[i]
                    string.append(strtemp)
                    strtemp = ''
                    tag = 0
                    j = i + 1
                    i += 1
            elif tag == 2:
                if str1[i] != '\'':
                    strtemp = strtemp + str1[i]
                    i = i + 1
                else:
                    strtemp = strtemp + str1[i]
                    string.append(strtemp)
                    strtemp = ''
                    tag = 0
                    j = i + 1
                    i += 1
        count = 0
        for sub in string:
            if sub == '':
                count += 1

        for i in range(count):
            string.remove('')

        createVariable(string, token)  #
        # print(token)
        # mapping function and variable
        j = 0
        while j < len(token):
            word = token[j]
            if word in constValue:  # 字面量
                j += 1
            elif j < len(token) and is_phor(variable, word):
                if word in keywords:
                    j += 1
                # new
                elif j - 1 >= 0 and j + 1 < len(token) and token[j - 1] == 'new' and token[j + 1] == '[':
                    j += 2
                elif j + 1 < len(token) and token[j + 1] == '(':  # 后面是( 则证明可能是方法
                    # print(token[j])
                    if index == 0:
                        list_func.append(token[j])
                    if 'doPost' in token[j] or 'doGet' in token[j]:
                        list_func.append(token[j])
                    if token[j] == 'doSomething' or token[j] == 'getNextNumber' or "good" in token[j] or "bad" in token[j] or 'privateReturns' in word:
                        if token[j] in _func_dict.keys():  # 已存入  key:old value:new
                            token[j] = _func_dict[token[j]]  # word -> 转化之后的
                            j += 2
                        else:
                            list_values = _func_dict.values()
                            if len(list_values) == 0:
                                _func_dict[token[j]] = 'func_0'
                                token[j] = _func_dict[token[j]]
                            else:
                                if token[j] in _func_dict.keys():
                                    token[j] = _func_dict[token[j]]
                                else:
                                    list_num = []
                                    for value in list_values:
                                        list_num.append(int(value.split('_')[-1]))
                                    _max = max(list_num)
                                    _func_dict[token[j]] = 'func_' + str(_max + 1)
                                    token[j] = _func_dict[token[j]]
                            j = j + 2
                    else:
                        j += 2
                # variable
                elif j + 1 < len(token) and (not is_phor(variable, token[j + 1])):
                    if word in _variable_dict.keys():
                        token[j] = _variable_dict[token[j]]
                        j += 2
                        continue
                    elif token[j + 1] == '.':  # 处理.的情况 可能需要改正
                        token1 = token[j + 2:]
                        str2 = word + '.'
                        m = j + 2
                        for t in token1:
                            if t != '.' and not is_phor(function, t):
                                break
                            if is_phor(function, t) and token[m-1] != '.':  # 后面是空格
                                break
                            str2 = str2 + t
                            m += 1
                        if str2 in keywords_7:
                            j = m
                            continue
                    if word in keywords_6 or word in keywords_7 or 'A'<=word[0] <='Z':
                        j += 2
                        continue
                    else:
                        list_values = _variable_dict.values()
                        if len(list_values) == 0:
                            _variable_dict[token[j]] = 'variable_0'
                            token[j] = _variable_dict[token[j]]

                        else:
                            if token[j] in _variable_dict.keys():
                                token[j] = _variable_dict[token[j]]
                            else:
                                list_num = []
                                for value in list_values:
                                    list_num.append(int(value.split('_')[-1]))

                                _max = max(list_num)
                                _variable_dict[token[j]] = 'variable_' + str(_max + 1)
                                token[j] = _variable_dict[token[j]]
                        j = j + 2
                # last token
                elif j + 1 == len(token):
                    if token[j] in keywords_6:
                        j += 1
                        continue
                    list_values = _variable_dict.values()
                    if len(list_values) == 0:
                        _variable_dict[token[j]] = 'variable_0'
                        token[j] = _variable_dict[token[j]]

                    else:
                        if token[j] in _variable_dict.keys():
                            token[j] = _variable_dict[token[j]]
                        else:
                            list_num = []
                            for value in list_values:
                                list_num.append(int(value.split('_')[-1]))

                            _max = max(list_num)
                            _variable_dict[token[j]] = 'variable_' + str(_max + 1)
                            token[j] = _variable_dict[token[j]]
                        break
                elif j + 1 < len(token) and is_phor(variable, token[j + 1]):  # 碰到 x instanceof y 的情况 hj
                    # print("1:" + token[j])
                    # print("2:" + token[j + 1])
                    if token[j] in _variable_dict.keys():
                        token[j] = _variable_dict[token[j]]
                    j += 1
                else:
                    j += 1
            elif j < len(token) and is_phor(number, word):
                j += 1
            elif j < len(token) and is_phor(stringConst, word):
                j += 1
            else:
                j += 1
        temp = ''
        i = 0
        while i < len(token):
            if i == len(token) - 1:
                temp = temp + token[i]
            else:
                temp = temp + token[i] + ' '
            i += 1

        list_code[index] = temp  # 转化为fun variable之后的字符串的形式
        index += 1
        # print(temp)

    return list_code, list_func