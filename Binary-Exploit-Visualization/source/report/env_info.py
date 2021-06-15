import os
import subprocess

def get_checksec_info(path):
    if not os.access(path, os.X_OK):
        print(path + " can't execute!")
        exit(1)
    res = subprocess.Popen("checksec " + path, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, \
                           close_fds=True)

    return res.stderr.read().decode('utf-8')


def get_os_info():
    return os.popen("uname -a").read()


def get_map_info(path):
    with open(path, "r") as f:
        info = f.read()
        f.close()
    return info

# str = (get_checksec_info("../../test/sample/easyheap"))
# print(get_os_info())