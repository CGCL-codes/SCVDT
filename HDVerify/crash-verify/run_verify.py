# coding=utf-8
# This is a sample Python2.7  script.
import argparse
import logging
import ConfigParser
import os
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
from gdbUtils import Reproduce, calculate_line_crash, save_crash_line
from utils import utils

log = logging.getLogger("run_verify")

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("-t", dest="target_bin", help="an target program to run", required=True)
    p.add_argument("-d", dest="homeDir", help="an Home directoy")
    p.add_argument("-i", dest="inputDir", help="input dir or crash dir ")
    p.add_argument("-b", dest="input_type", help="binary input type [symfile]| [stdin]")
    return p.parse_args()

class Verify(object):
    def __init__(self, config):
        self.config = config
        self.get_verify_config()


    def get_verify_config(self):
        config = ConfigParser.ConfigParser()
        config.read(self.config)
        self.target_bin = config.get("main", "target_bin")
        self.input_file = config.get("main", "input_file")
        self.output_dir = config.get("main", "output_dir")
        self.input_type = config.get("main", "input_type")

    # def getTargetLine(self):
    #     pass


# Press the green button in the gutter to run the script.

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    args = parse_args()
    print args.target_bin
    print args.homeDir
    print args.inputDir
    print args.input_type
    target_bin = args.target_bin
    output_dir = os.path.join(args.homeDir, "crashVerifyTMP")
    input_type = args.input_type
    input_dir = args.inputDir
    crash_line_save_path = os.path.join(args.homeDir, "crash_line_function.txt")
    log.debug("start gdb test")

    # target_bin = "/root/aflgo-fuzz/build/out/207/noinstrument/jasper -f @@ -t mif -F /tmp/out -T jpg"
    # output_dir = "/root/aflgo-fuzz/build/out/207/crashVerifyTMP"
    # input_type = "symfile"
    # input_dir = "/root/aflgo-fuzz/build/outBak/207/fuzzer_dir/crashes"
    # crash_line_save_path = "/root/aflgo-fuzz/build/out/207/crash_line_function.txt"

    crash_line_list_function = calculate_line_crash(target_bin, input_dir, output_dir, input_type)
    # #保存
    save_crash_line(crash_line_save_path, crash_line_list_function)

    # -t "/root/aflgo-fuzz/build/out/207/noinstrument/jasper -f @@ -t mif -F /tmp/out -T jpg" -d "/root/aflgo-fuzz/build/out/207/"  -i "/root/aflgo-fuzz/build/outBak/207/fuzzer_dir/crashes" -b symfile


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
