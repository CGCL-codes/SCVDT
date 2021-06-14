import os

from py2neo import NodeMatcher, Graph

import sys


def sort_down(nodes):
    return sorted(nodes, key=lambda k: k['a']['startLine'], reverse=True)


def sort_up(nodes):
    return sorted(nodes, key=lambda k: k['b']['startLine'], reverse=False)


def bubbleSort(nums):
    for i in range(len(nums) - 1):  # 遍历 len(nums)-1 次
        for j in range(len(nums) - i - 1):  # 已排好序的部分不用再次遍历
            if nums[j]['startLine'] > nums[j + 1]['startLine']:
                nums[j], nums[j + 1] = nums[j + 1], nums[j]  # Python 交换两个数不用中间变量
            elif nums[j]['startLine'] == nums[j + 1]['startLine'] and nums[j + 1].has_label('METHOD'):
                nums[j], nums[j + 1] = nums[j + 1], nums[j]
    return nums


# 前向的函数依赖返回
def program_cross_forwards(methodNode, db):
    list_nodes = []

    list_nodes.append(methodNode)
    enterNodes = db.run("MATCH (a) -[:ENTER]->(b) where ID(a)="
                        + str(methodNode.identity) + " return b").data()
    for enterNode in enterNodes:
        if enterNode['b']['code'] == 'Enter':
            allCCNodes = db.run("MATCH (a) -[:CD]->(b) where ID(a)="
                                + str(enterNode['b'].identity) + " return b").data()
            if len(allCCNodes) == 0 or allCCNodes is None:
                return list_nodes
            else:
                for node in allCCNodes:
                    list_nodes.append(node['b'])
                bubbleSort(list_nodes)
                return list_nodes
    return list_nodes


def process_cross_func_backward(list_nodes, db, node_one):
    global list_results
    i = 0
    j = 0
    for res_node in list_results:
        if res_node.identity == node_one.identity:
            j = i
            break
        i += 1
    pre = list_results[0:j]
    last = list_results[j:]
    temp = []
    temp.extend(pre)
    temp.extend(list_nodes)
    temp.extend(last)
    list_results = temp

    for node in list_nodes:
        if node.has_label('METHOD'):

            cross_backwards = db.run("MATCH (a) -[:DD]->(b) where ID(b)="
                                     + str(node.identity) + " return a").data()
            if len(cross_backwards) == 0 or cross_backwards is None:
                if not node_one:
                    continue
                else:
                    return

            for crossNode in cross_backwards:
                list_result = program_slice_backwards(crossNode['a'], db)

                process_cross_func_backward(list_result, db, node)
        else:  # TODO 待验证
            # 前向的调用
            cross_forwards = db.run("MATCH (a) -[:DD]->(b:METHOD) where ID(a)="
                                    + str(node.identity) + " return b").data()
            if len(cross_forwards) == 0 or cross_forwards is None:
                if node_one == []:
                    continue
                else:
                    return
            for crossNode in cross_forwards:
                list_result_forwards = program_cross_forwards(crossNode['b'], db)  # 找到所有的前向
                i = 0
                j = 0
                for temp in list_results:
                    if temp.identity == node.identity:
                        j = i
                        break
                    i += 1
                pre = list_results[0:j + 1]
                last = list_results[j + 1:]
                temp_list = []
                temp_list.extend(pre)
                temp_list.extend(list_result_forwards)
                temp_list.extend(last)
                list_results = temp_list

                # process_cross_func_forward(list_result_forwards, db) TODO 多个sink和source


# 初始节点的后向 过程内


def sub_slice_backwards(node, db, list_nodes, list_node_id):
    if node.has_label('METHOD'):
        if node.identity not in list_node_id:
            list_nodes.append(node)
            list_node_id.append(node.identity)
        return
    elif node['code'] == 'Enter':
        methodNode = db.run("MATCH (a) -[:ENTER]->(b) where ID(b)="
                            + str(node.identity) + " return a").data()
        sub_slice_backwards(methodNode[0]['a'], db, list_nodes, list_node_id)
    else:
        if node.identity not in list_node_id:
            list_nodes.append(node)
            list_node_id.append(node.identity)
        else:
            return
        backwardNodes = db.run("MATCH (a) -[:DD|CD|ENTER]->(b) where ID(b)="
                               + str(node.identity) + " return a").data()
        sort_down(backwardNodes)
        for value in backwardNodes:
            sub_slice_backwards(value['a'], db, list_nodes, list_node_id)


def program_slice_backwards(node, db):
    list_nodes = []
    list_node_id = []
    backwardNodes = db.run("MATCH (a) -[:DD|CD|ENTER]->(b) where ID(b)="
                           + str(node.identity) + " return a").data()
    if len(backwardNodes) == 0:
        return list_nodes
    sort_down(backwardNodes)

    for value in backwardNodes:
        sub_slice_backwards(value['a'], db, list_nodes, list_node_id)

    list_nodes.append(node)
    bubbleSort(list_nodes)
    # for node in list_nodes:
    #     print(node['startLine'])

    # 程序间
    # list_result.extend(list_nodes)
    # process_cross_func(list_nodes, db)
    return list_nodes


# 每一个节点的前向数据依赖
def sub_slice_forwards(node, db, list_nodes, list_nodes_id):
    if node.has_label('METHOD'):
        return
    elif node['code'] == 'Enter':
        print("node can not be enter node")
    else:
        if node.identity not in list_nodes_id:
            list_nodes.append(node)
            list_nodes_id.append(node.identity)
        else:
            return
        forwardNodes = db.run("MATCH (a) -[:DD|ENTER]->(b) where ID(a)="
                              + str(node.identity) + " return b").data()
        if len(forwardNodes) == 0 or forwardNodes is None:
            return
        sort_up(forwardNodes)
        for value in forwardNodes:
            sub_slice_forwards(value['b'], db, list_nodes, list_nodes_id)


# 关注点的前向数据依赖
def program_slice_forwards(node, db):
    list_nodes = []
    list_nodes_id = []
    forwardNodes = db.run("MATCH (a) -[:DD|ENTER]->(b) where ID(a)="
                          + str(node.identity) + " return b").data()
    if len(forwardNodes) == 0 or forwardNodes is None:
        return list_nodes
    sort_up(list_nodes)

    for value in forwardNodes:
        sub_slice_forwards(value['b'], db, list_nodes, list_nodes_id)

    bubbleSort(list_nodes)
    return list_nodes


def process_cross_func_forward(result_forwards, db, node_one):
    global list_results
    i = 0
    j = 0
    for temp in list_results:
        if temp.identity == node_one.identity:
            j = i
        i += 1
    pre = list_results[0:j + 1]
    last = list_results[j + 1:]
    temp_list = []
    temp_list.extend(pre)
    temp_list.extend(result_forwards)
    temp_list.extend(last)
    list_results = temp_list

    for node in result_forwards:
        cross_forwards = db.run("MATCH (a) -[:DD]->(b:METHOD) where ID(a)="
                                + str(node.identity) + " return b").data()
        if len(cross_forwards) == 0 or cross_forwards is None:
            if [] == node_one:
                continue
            else:
                return
        for crossNode in cross_forwards:
            return_nodes = program_cross_forwards(crossNode['b'], db)  # 获取该函数下的所有节点
            # 遍历所有的节点 看是否存在前向的函数数据依赖
            process_cross_func_forward(return_nodes, db, node)


def delete_s(s):
    s_n = []
    for line in s:
        line = line.strip().strip('\n').strip().strip('{').strip('}').strip()
        s_n.append(line)
    return s_n


def getMethodEnd(records, index):
    start = index
    end = index
    for line in records:
        line = line.strip().strip('\n').strip()
        if line[0:2] != '/*' and line[0] != '*' and line[0:2] != '//':
            if 'public' in line or 'protected' in line or 'private' in line:
                start = index
            if '{' in line:
                end = index
                break
        index += 1

    return start, end


def writeStr(node, f, _dict, db):
    if node.has_label('METHOD'):
        with open(node['filePath'], 'r') as file:
            records = file.readlines()
            index = node['startLine']
            start, end = getMethodEnd(records[index - 1:], index - 1)
            s = records[start:end + 1]
            s = delete_s(s)
            a = start + 1
            lines = []
            for l in s:
                f.write(l + " " + str(a) + '\n')
                lines.append(a)  # lines以1开头
                a += 1
            # s = records[index - 1]
            # s = s.strip().strip('\n').strip().strip('{').strip('}').strip()
            # f.write(s + " " + str(index) + '\n')
            file.close()
            # lines = []
            # lines.append(index)
            _dict[node['code']] = lines
    else:
        method = db.run("MATCH (a) where ID(a)=" + str(node['methodID']) + " return a").data()
        with open(method[0]['a']['filePath'], 'r') as file:
            records = file.readlines()
            file.close()
            index = node['startLine']
            end = node['endLine']
            methodName = method[0]['a']['code']
            if methodName in _dict.keys():
                lines = _dict[methodName]
                if index in lines:
                    return
                else:
                    s = records[index - 1:end + 1 - 1]
                    s = delete_s(s)
                    a = index
                    for line in s:
                        f.write(line + " " + str(a) + '\n')
                        lines.append(a)
                        a += 1
                    _dict[methodName] = lines
            else:
                lines = []
                s = records[index - 1:end + 1 - 1]
                s = delete_s(s)
                a = index
                for line in s:
                    f.write(line + " " + str(a) + '\n')
                    lines.append(a)
                    a += 1
                _dict[methodName] = lines


def writeFile(backward_nodes, forward_nodes, node, dir, types, db):
    method = db.run("MATCH (a:METHOD) where ID(a)=" + str(node['methodID']) + " return a").data()
    if len(method) == 0:
        print("node error")
        return
    dirName = method[0]['a']['dirName']
    filePath = method[0]['a']['filePath']
    index = filePath.rfind(os.sep)
    if index == -1:
        print("文件路径出错")
        return

    fileName = filePath.split(os.sep)[-1].replace(".java", "")

    type_name = ""
    if types == 0:
        type_name = "AE"
    elif types == 1:
        type_name = "MI"
    else:
        type_name = "SE"

    #  types dirName 方法名 id
    txt = os.path.join(dir, str(id) + "_" + type_name + "_" + dirName + "_" + method[0]['a']['code'] + '.txt')
    if os.path.exists(txt):
        print("path exists")
        return

    f = open(txt, 'w', encoding='utf-8')
    index = filePath.rfind(os.sep)
    if index == -1:
        print("文件路径出错")
        return
    code = node['code'].replace('\n', '\\n')

    # dir名 文件路径 代码 代码位置
    f.write(dirName + " " + filePath + " " + code + " " + str(node['startLine']))
    f.write('\n')

    # methodNode = None
    _dict = {}
    for node in backward_nodes:
        writeStr(node, f, _dict, db)
    for node in forward_nodes:
        writeStr(node, f, _dict, db)

    label = 0
    f.write(str(label))
    f.close()


def get_slice(db, types, dir):
    global id
    matcher = NodeMatcher(db)
    result = matcher.match("EXPRESSION", type=types)
    # id = 0
    for node in iter(result):
        list_results.clear()
        # 获取后向依赖
        # print("backward begin......")
        result_backwards = program_slice_backwards(node, db)
        process_cross_func_backward(result_backwards, db, [])
        backward_nodes = list_results.copy()

        list_results.clear()
        # print("backward over!")

        # 获取前向依赖 只有数据依赖
        # print("forward begin......")
        result_forwards = program_slice_forwards(node, db)
        process_cross_func_forward(result_forwards, db, [])
        forward_nodes = list_results.copy()
        list_results.clear()
        # print("forward over!")

        # print("write into file..." + '\n')
        if len(forward_nodes) == 0 and len(backward_nodes) == 2:
            continue
        writeFile(backward_nodes, forward_nodes, node, dir, types, db)
        id += 1
    # print("\nover\n")


url = "http://localhost:7474"
username = "neo4j"
password = "snail"


# 连接数据库
def connect_neo4j():
    graph = Graph(url, username=username, password=password)
    return graph


list_results = []
id = 0


def start(slicePath):
    print("获取切片")
    db = connect_neo4j()
    lists = [0, 1, 2]
    for types in lists:
        get_slice(db, types, slicePath)

    # 删除所有的数据 标签 CLASS, METHOD, EXPRESSION
    db.run('match (n:CLASS) detach delete n')
    db.run("match (n:METHOD) detach delete n")
    db.run("match (n:EXPRESSION) detach delete n")
    db.run("match (n:DIRECTORY) detach delete n")

    print("获取切片结束")
