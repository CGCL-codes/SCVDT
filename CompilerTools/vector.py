from optparse import OptionParser
import multiprocessing
import numpy as np
import subprocess
import tempfile
import joblib
import utils
import time
import os

csp = ''
GCOV_VISION = ''
GCC_PATH = ''

normalizer_time = joblib.load('model/normal_time')
clf_time = joblib.load('model/time.pkl')

index = []
with open('model/no_same_no_neg.txt', 'r') as f:
    for line in f:
        index.append(int(line.strip()))
index = index[:-1]
index = sorted(index)

def get_reduce_index(file, ind):
    indices = []
    with open(file, 'r') as afi:
        for line in afi:
            indices.append(int(line.strip()))
    index = indices[:ind]
    index = sorted(index)
    return index

time_reduce_index = get_reduce_index('model/index_time_all.txt', 2920)

def execute(seed, path=os.getcwd()):
    filename = str(seed)
    gcc_command = '(cd ' + path + '; ' + GCC_PATH + ' -O0 -w ' + ' -I${CSMITH_HOME}/runtime ' + filename + '.c -o ' + filename + ')'
    subprocess.call(gcc_command, cwd=path, shell=True)

def run_gcov_branch(ofile):
    path, file_name = os.path.split(ofile)
    gcov_command = '(cd ' + path + '; ' + GCOV_VISION + ' -b ' + file_name + '.o)'
    subprocess.call(gcov_command, shell=True, stdout=open('/dev/null', 'w'))

def multi_run(file_list):
    start_time = time.time()
    proc_num = 2
    pool = multiprocessing.Pool(proc_num)
    for ofile in file_list:
        pool.apply_async(run_gcov_branch, args=(ofile,))
    pool.close()
    pool.join()
    end_time = time.time()
    print('gcov time: ' + str(end_time - start_time))

def get_file_feature(file):
    branch_info = []
    file_name = file + '.c.gcov'
    with open(file_name, 'r', encoding='iso8859') as f:
        lines = f.readlines()
        for i in range(1, len(lines)):
            prev = lines[i - 1]
            cur = lines[i]
            if 'branch' in cur:
                if ':' not in cur and 'function' not in cur:
                    split_line = cur.strip().split()
                    if '(' in cur:
                        info = int(split_line[-2].strip('%'))
                        branch_info.append(info)
                    else:
                        if 'never' in cur:
                            info = 0
                            branch_info.append(info)
                        else:
                            info = int(split_line[-1].strip('%'))
                            branch_info.append(info)
    return branch_info

def select(file_list, seed=1):
    file_list = sorted(file_list)
    feature = []
    for file in file_list:
        tmp = get_file_feature(file)
        feature.extend(tmp)
    feature.append(int(seed))
    print(len(feature))
    feature = np.array(feature)
    no_same_feature = feature[index]
    time_feature = no_same_feature[time_reduce_index]
    time_feature = normalizer_time.fit_transform(time_feature.reshape(1, -1))
    time_res = clf_time.predict(time_feature)
    if time_res[0] == 1:
        return 0
    elif time_res[0] == 0:
        return 1

def file_process(file_name):
    pos = 'Error'
    print(file_name)
    file_to_remove = utils.get_file(csp, '.gcda')
    utils.remove_file(file_to_remove)
    subprocess.run(GCC_PATH + ' -O0 -w -I${CSMITH_HOME}/runtime ' + file_name + ' -o test0', shell=True)

    run_file_list = utils.get_file(csp, '.gcda')
    if len(run_file_list) != 290:
        if os.path.exists('test0'):
            subprocess.run('rm test0', shell=True)
        pos = -1
        return pos
    multi_run(run_file_list)
    pos = select(run_file_list)
    if os.path.exists('test0'):
        subprocess.run('rm test0', shell=True)
    return pos

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-c', '--source_file_path', type=str, default='', help='gcc source file path')
    parser.add_option('-v', '--gcov_version', type=str, default='', help='gcov version')
    parser.add_option('-p', '--gcc_path', type=str, default='', help='gcc path')
    parser.add_option('-f', '--file', type=str, default='', help='file path')

    (options, args) = parser.parse_args()

    csp = '/home/wujc/Documents/gcc-tools/gcc-build/gcc'
    GCOV_VISION = '/home/wujc/local/gcc-4.4.0/bin/gcov'
    GCC_PATH = '/home/wujc/local/gcc-4.4.0/bin/gcc'

    csp = options.source_file_path
    GCOV_VISION = options.gcov_version
    GCC_PATH = options.gcc_path
    code = options.file

    time_out = file_process(code)
    print(time_out)