# coding=utf-8
import os
import sys
import multiprocessing
import logging
import time
import re

from utils import utils
log = logging.getLogger("reproduce")

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))

class Reproduce(object):

    def __init__(self, target_bin, output_dir, input_type=None):
        self.target_bin = target_bin
        self.output_dir = output_dir
        self.input_type = input_type
        self.run_log = os.path.join(self.output_dir, "run.log")
        self.tmp_target_bin = target_bin


    ## 使用input 替換"@@"
    def fix_at_file(self):
        target_bin_list = self.target_bin.split(" ")
        if "@@" in target_bin_list:
            idx = target_bin_list.index("@@")
            target_bin_list[idx] = self.input_file
            self.target_bin = " ".join(target_bin_list)
            # log.debug("[fix_at_file] %s"%self.target_bin)

    # 为不同的输入生成gdbinit文件
    def gen_gdbInit(self):
        if self.input_type == "symfile":
            self.gdbinit = os.path.join(PROJECT_DIR, "gdbUtils", "gdbinit")
        elif self.input_type == "stdin":
            content = "run < " + self.input_file + "\n"
            content += "backtrace\n"
            content += "quit\n"
            tempFilePath = os.path.join(PROJECT_DIR, "gdbUtils", "gdbinitSTDFIN")
            with open(tempFilePath, 'w') as f:
                f.write(content)
            self.gdbinit = tempFilePath
        else:
            pass


    def gen_runTarget_cmd(self):
        cmd = []
        cmd += ["gdb", "-q", "--batch"]
        self.gen_gdbInit()
        cmd += ["-x", self.gdbinit]
        cmd += ["--args", self.target_bin]
        return cmd

    #　step1: 生成gdb調試的日志
    def generatorGDBLog(self):
        # 　組裝命令
        if self.input_type == "symfile":
            self.target_bin = self.tmp_target_bin
            self.fix_at_file()
        # print self.target_bin
        xargs = self.gen_runTarget_cmd()

        fout = self.run_log
        utils.mkdir_force(self.output_dir)
        kw = {'output': fout, 'use_shell': True}

        log.debug("starting gdb: %s" % ' '.join(xargs))
        p = multiprocessing.Process(target=utils.exec_async, args=[xargs], kwargs=kw)
        # print "starting gdb: ", " ".join(xargs)

        p.start()

    #　step2: 获取运行日志栈信息
    def getStackInfoFromLog(self):
        try_num = 5
        flag = False
        while try_num > 0:
            if os.path.exists(self.run_log):
                flag = True
                break
            time.sleep(3)
            try_num -= 1

        if flag == False:
            log.debug("[error]: no run.log")

        stackInfo = []
        with open(self.run_log, "r") as f:
            for line in f:
                if line.startswith("#"):
                    # print line
                    fileterMatch1 = re.sub("\\(.*?\\)", "", line)
                    fileterMatch2 = re.sub("0x[0-9a-fA-F]* ", "", fileterMatch1)
                    fileterMatch3 = re.sub("[\s]in[\s]", " ", fileterMatch2)
                    fileterMatch4 = re.sub("[\s]at[\s]", " ", fileterMatch3)
                    # print fileterMatch4

                    temp = fileterMatch4.split()
                    # print temp
                    dictItem = {}
                    if len(temp) >= 3:
                        dictItem["id"] = temp[0]
                        dictItem["functionName"] = temp[1]
                        dictItem["line"] = temp[2]
                        stackInfo.append(dictItem)

        return stackInfo

    # step3: 获取程序源码中崩溃的行
    def getLineFromStack(self,stackInfo):
        line = None
        for item in stackInfo:
            if item["functionName"].startswith("_"):
                continue
            else:
                line = item["line"]
                break
        return item


    def get_target_line_function(self, input_file):
        self.input_file = input_file

        # 获取运行日志
        self.generatorGDBLog()
        log.debug("[get_target_line] gen GDB log successfully")

        # 提取栈信息
        stackInfo = self.getStackInfoFromLog()
        # print stackInfo
        log.debug("[get_target_line] get stack info from log  successfully")
        #
        # # 提取出程序中的行
        if stackInfo:
            item = self.getLineFromStack(stackInfo)
            return item
        else:
            pass

        # print line
        return None

        # time.sleep(4)

# 为给定的crash文件夹下的所有crash计算出对应的行
# target_bin:目标执行程序路径＋参数
# input_dir: crash文件夹
# output_dir:　输出文件夹
# input_type : 输入类型　stdin/symfile
def calculate_line_crash(target_bin, input_dir, output_dir, input_type):
    # 读取文件夹下的所有文件
    fileList = os.listdir(input_dir)
    result_list = []
    if fileList:
        reprocuce = Reproduce(target_bin, output_dir, input_type)
        for fp in fileList:
            if fp.startswith("id"):
                input_file_path = os.path.join(input_dir, fp)
                item  = reprocuce.get_target_line_function(input_file_path) #行和崩潰函數

                dict_item = {}
                if item:
                    #可以获得崩溃行
                    dict_item["crash_name"] = fp
                    dict_item["line"] = item["line"]
                    dict_item["functionName"] = item["functionName"]
                    result_list.append(dict_item)
                else:
                    # 无法获得 崩溃行，是空的
                    pass

                # print input_file_path
                # print line
    else:
        log.debug("[calculate_line_crash] %s is empty or not exist" % input_dir)

    return result_list

# 将crash_line_List集合中的内容保存至save_path路径下面
def save_crash_line(save_path, crash_line_list):
    if crash_line_list:
        with open(save_path, 'a') as f:
            for item in crash_line_list:
                f.write("{0}#{1}#{2}\n".format(item["crash_name"], item["line"], item["functionName"]))
    else:
        log.debug("[save_crash_line] crash_line_list is empty")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    print PROJECT_DIR
    # target_bin = "/root/desktop/vulnForVerify/vuln"
    # input_file = "/root/desktop/vulnForVerify/crashes/id:000001,5557,sig:11,src:000002,op:havoc,rep:2"
    # # input_file = "/root/desktop/vulnForVerify/crashes/id:000000,872,sig:11,src:000000,op:havoc,rep:128"
    # output_dir = "/root/desktop/vulnForVerify/output_dir"
    # input_type = "stdin"

    # target_bin = "/root/aflgo-fuzz/build/out/207/noinstrument/jasper -f @@ -t mif -F /tmp/out -T jpg"
    # # input_file = "/root/desktop/vulnForVerify/crashes/id:000001,5557,sig:11,src:000002,op:havoc,rep:2"
    # # # input_file = "/root/desktop/vulnForVerify/crashes/id:000000,872,sig:11,src:000000,op:havoc,rep:128"
    # output_dir = "/root/aflgo-fuzz/build/out/207/crashVerifyTMP"
    # input_type = "symfile"
    # input_dir = "/root/aflgo-fuzz/build/outBak/207/fuzzer_dir/crashes"
    # crash_line_list_function = calculate_line_crash(target_bin, input_dir, output_dir, input_type)

    target_bin = "/root/aflgo-fuzz/build/out/235/noinstrument/vulnerable"
    input_dir = "/root/test/crashes"
    output_dir = "/root/test/verifyTMP"
    input_type = "stdin"
    crash_line_list_function = calculate_line_crash(target_bin, input_dir, output_dir, input_type)
    #保存
    crash_line_save_path = "/root/test/crash_line_function.txt"
    save_crash_line(crash_line_save_path, crash_line_list_function)



