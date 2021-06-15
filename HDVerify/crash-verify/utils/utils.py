# coding=utf-8
import subprocess
import os
AT_FILE = "@@"


def mkdir_force(abs_dir):
    """
    create new dir, rm the old one if exists
    """
    if os.path.exists(abs_dir):
        # print ['rm', '-rf', abs_dir]
        subprocess.Popen(['rm', '-rf', abs_dir]).wait()
    os.makedirs(abs_dir)

def exec_sync(cmd, working_dir=None, env=None, use_shell=False):
    if env is not None:
        os.environ=env
    subprocess.call(cmd, shell=use_shell)

def signal_ignore(arg1, arg2):
    pass
    # os._exit(0)

# 异步运行
def exec_async(cmd, mock_eof=False, working_dir=None, use_shell=False, env=None, output=None, mem_cap=None):
    # print "[exec_saync start]"
    fin = None
    fout = None
    if mock_eof:
        fin=open(os.devnull)

    if output is not None:
        parentPath = os.path.dirname(output)
        if not os.path.exists(parentPath):
            os.mkdir(parentPath)
        fout=open(output, 'w')  #打印gdb的日志記錄

    if env is not None:
        os.environ=env

    if mem_cap is not None:
        cmd = ["ulimit -v " + mem_cap + ";"] + cmd

    if use_shell:
        cmd = ' '.join(cmd)

    p = subprocess.Popen(cmd, shell=use_shell, stdin=fin, stdout=fout)
    return p.wait()

    # print "[exec_saync end]"



