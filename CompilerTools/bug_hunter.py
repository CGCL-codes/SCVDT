import os
import utils
import subprocess
from optparse import OptionParser

gcc_install_path = ''
git_home = ''
gmp_home = ''
mpfr_home = ''
mpc_home = ''
bug_path = ''

gcc_list = ["gcc-4.4.0", "gcc-4.4.1", "gcc-4.4.2", "gcc-4.4.3", "gcc-4.4.4", "gcc-4.4.5", "gcc-4.4.6", "gcc-4.4.7", "gcc-4.5.0", "gcc-4.5.1", "gcc-4.5.2", "gcc-4.5.3", "gcc-4.5.4", "gcc-4.6.0", "gcc-4.6.1", "gcc-4.6.2", "gcc-4.6.3", "gcc-4.6.4", "gcc-4.7.0", "gcc-4.7.1", "gcc-4.7.2", "gcc-4.7.3", "gcc-4.7.4", "gcc-4.8.0", "gcc-4.8.1", "gcc-4.8.2", "gcc-4.8.3", "gcc-4.8.4", "gcc-4.8.5", "gcc-4.9.0", "gcc-4.9.1", "gcc-4.9.2", "gcc-4.9.3", "gcc-4.9.4", "gcc-5.1.0", "gcc-5.2.0", "gcc-5.3.0", "gcc-5.4.0", "gcc-5.5.0", "gcc-6.1.0", "gcc-6.2.0", "gcc-6.3.0", "gcc-6.4.0", "gcc-6.5.0", "gcc-7.1.0", "gcc-7.2.0", "gcc-7.3.0", "gcc-7.4.0", "gcc-7.5.0", "gcc-8.1.0", "gcc-8.2.0", "gcc-8.3.0"]
commit_dict = {'5bfae70': '4_4', '086e186': '4_4', '331fec9': '4_5', '41eccc8': '4_5', '0dfc7a9': '4_6', '66cc0b3': '4_6', '331722c': '4_7', '4d1f511': '4_7', 'ecffed6': '4_8', '2a62b04': '4_8', '3ec1afb': '4_9', '4f18db5': '4_9', 'ea29f08': '5', '926d994': '5', '0e329f8': '6', '39a300f': '6', '6eceeed': '7', 'b2d961e': '7', 'dc5c5ba': '8', '4c44b70': '8'}
branch_dict = {'4_4': ['086e186', '5bfae70'], '4_5': ['41eccc8', '331fec9'], '4_6': ['66cc0b3', '0dfc7a9'], '4_7': ['4d1f511', '331722c'], '4_8': ['2a62b04', 'ecffed6'], '4_9': ['4f18db5', '3ec1afb'], '5': ['926d994', 'ea29f08'], '6': ['39a300f', '0e329f8'], '7': ['b2d961e', '6eceeed'], '8': ['4c44b70', 'dc5c5ba']}

def get_gcc_list(start_gcc_ver):
    gcc_list = []
    with open('gcc-log/gcc-tag.txt', 'r') as fg:
        lines = fg.readlines()
        cnt = 0
        start_cnt = 0
        while cnt < len(lines):
            new_line = lines[cnt]
            if start_gcc_ver not in new_line:
                cnt += 1
                continue
            else:
                start_cnt = cnt
                break
        while start_cnt < len(lines):
            new_line = lines[start_cnt]
            if 'gcc' not in new_line:
                break
            gcc_ver = new_line.strip().split('/')[-1]
            gcc_list.append(gcc_ver)
            start_cnt += 1
    return gcc_list

def clear_path():
    pass_list = list(commit_dict.keys())
    all_gcc_list = os.listdir(gcc_install_path)
    gcc_to_remove = list(set(all_gcc_list) - set(pass_list))
    remove_commit = gcc_to_remove[0]
    rm_cmd = 'rm -rf ' + gcc_install_path + '/' + remove_commit
    rm_p = subprocess.Popen(rm_cmd, shell=True)
    rm_p.communicate()

def write_data_to_file(file, data):
    front_data = ""
    after_data = "" 
    with open(file, "r+", encoding="u8") as fp:
        for i, d in enumerate(fp.readlines(), start=1):
            if i >= 32:
                after_data += d
            else:
                front_data += d
        fp.seek(0)
        fp.write(front_data)
        fp.write(data + "\n")
        fp.write(after_data)
        fp.truncate()

def replace_source_file():
    # 4.4.0
    file_to_replace_1 = git_home + '/config/i386/linux-unwind.h'
    # 4.7.0
    file_to_replace_7 = git_home + '/gcc/config/i386/linux-unwind.h'
    # 4.9.0
    file_to_replace_2 = git_home + '/libgcc/config/i386/linux-unwind.h'
    file_to_replace_3 = git_home + '/libsanitizer/sanitizer_common/sanitizer_stoptheworld_linux_libcdep.cc'
    file_to_replace_4 = git_home + '/libsanitizer/sanitizer_common/sanitizer_linux.h'
    file_to_replace_5 = git_home + '/libsanitizer/asan/asan_linux.cc'
    file_to_replace_6 = git_home + '/libsanitizer/tsan/tsan_platform_linux.cc'
    if os.path.exists(file_to_replace_1):
        with open(file_to_replace_1, '+r') as replace_f1:
            buf = replace_f1.read()
            buf = buf.replace('struct siginfo', 'siginfo_t')
            buf = buf.replace('struct ucontext', 'ucontext_t')
            replace_f1.seek(0, 0)
            replace_f1.write(buf)
            replace_f1.truncate()
    elif os.path.exists(file_to_replace_2):
        with open(file_to_replace_2, '+r') as replace_f2:
            buf = replace_f2.read()
            buf = buf.replace('struct siginfo', 'siginfo_t')
            buf = buf.replace('struct ucontext', 'ucontext_t')
            replace_f2.seek(0, 0)
            replace_f2.write(buf)
            replace_f2.truncate()
    elif os.path.exists(file_to_replace_7):
        with open(file_to_replace_7, '+r') as replace_f7:
            buf = replace_f7.read()
            buf = buf.replace('struct siginfo', 'siginfo_t')
            buf = buf.replace('struct ucontext', 'ucontext_t')
            replace_f7.seek(0, 0)
            replace_f7.write(buf)
            replace_f7.truncate()
    if os.path.exists(file_to_replace_3):
        with open(file_to_replace_3, '+r') as replace_f3:
            buf = replace_f3.read()
            buf = buf.replace('struct sigaltstack', 'stack_t')
            replace_f3.seek(0, 0)
            replace_f3.write(buf)
            replace_f3.truncate()
    if os.path.exists(file_to_replace_4):
        with open(file_to_replace_4, '+r') as replace_f4:
            buf = replace_f4.read()
            buf = buf.replace('const struct sigaltstack* ss', 'const void* ss')
            buf = buf.replace('struct sigaltstack* oss', 'void* oss')
            replace_f4.seek(0, 0)
            replace_f4.write(buf)
            replace_f4.truncate()
    if os.path.exists(file_to_replace_5):
        write_data_to_file(file_to_replace_5, '#include <signal.h>')
    if os.path.exists(file_to_replace_6):
        with open(file_to_replace_6, '+r') as replace_f6:
            buf = replace_f6.read()
            buf = buf.replace('__res_state *statp = (__res_state*)state', 'struct __res_state *statp = (struct __res_state*)state')
            replace_f6.seek(0, 0)
            replace_f6.write(buf)
            replace_f6.truncate()

def gen_compiler(commit):
    print('install: ' + commit)
    if not os.path.isdir(gcc_install_path + '/' + commit):
        distclean = 'make distclean'
        subprocess.call(distclean, shell=True, cwd=git_home, stdout=open('/dev/null', 'w'))
        # clear_path()
        checkout = 'git checkout -f ' + commit
        subprocess.call(checkout, shell=True, cwd=git_home, stdout=open('/dev/null', 'w'))
        replace_source_file()
        install_home = gcc_install_path + '/' + commit
        config_command = '../gcc/configure LDFLAGS=-Wl,--no-as-needed --prefix=%s --with-gmp=%s --with-mpfr=%s --with-mpc=%s --enable-languages=c,c++ --disable-multilib --disable-bootstrap'%(install_home, gmp_home, mpfr_home, mpc_home)
        make_command = 'make'
        install_command = 'make install'
        config_p = subprocess.Popen(config_command, shell=True, cwd=git_home)
        config_p.communicate()
        make_p = subprocess.Popen(make_command, shell=True, cwd=git_home)
        make_p.communicate()
        if make_p.returncode != 0:
            return -1
        install_p = subprocess.Popen(install_command, shell=True, cwd=git_home)
        install_p.communicate()
    return 0

def evaluate(code, gcc):
    subprocess.run(gcc + ' ' + code + ' -O0 -I${CSMITH_HOME}/runtime -w -o a0', shell=True)
    subprocess.run(gcc + ' ' + code + ' -O1 -I${CSMITH_HOME}/runtime -w -o a1', shell=True)
    subprocess.run(gcc + ' ' + code + ' -O2 -I${CSMITH_HOME}/runtime -w -o a2', shell=True)
    subprocess.run(gcc + ' ' + code + ' -O3 -I${CSMITH_HOME}/runtime -w -o a3', shell=True)
    subprocess.run(gcc + ' ' + code + ' -Os -I${CSMITH_HOME}/runtime -w -o as', shell=True)
    try:
        subprocess.run(['./a0'], timeout=15, check=True, stdout=open('out_0', 'w'))
        subprocess.run(['./a1'], timeout=15, check=True, stdout=open('out_1', 'w'))
        subprocess.run(['./a2'], timeout=15, check=True, stdout=open('out_2', 'w'))
        subprocess.run(['./a3'], timeout=15, check=True, stdout=open('out_3', 'w'))
        subprocess.run(['./as'], timeout=15, check=True, stdout=open('out_s', 'w'))

        all_res = []
        diff_opt = ['1', '2', '3', 's']
        for option_level in diff_opt:
            cmd = 'diff out_0 out_' + option_level
            out_file = 'diff_' + option_level
            subprocess.call(cmd, shell=True, stdout=open(out_file, 'w'))
            with open(out_file, 'r') as out_f:
                all_res.append(out_f.readlines())
        if not (len(all_res[0]) == 0 and len(all_res[1]) == 0 and len(all_res[2]) == 0 and len(all_res[3]) == 0):
            subprocess.run('rm a*', shell=True)
            subprocess.run('rm out_*', shell=True)
            subprocess.run('rm diff_*', shell=True)
            return 0
        else:
            subprocess.run('rm a*', shell=True)
            subprocess.run('rm out_*', shell=True)
            subprocess.run('rm diff_*', shell=True)
            return 1
    except subprocess.TimeoutExpired as e:
        print('time out!')
        subprocess.run('rm a*', shell=True)
        subprocess.run('rm out_*', shell=True)
        subprocess.run('rm diff_*', shell=True)
        return 0
    except subprocess.CalledProcessError as e:
        print('error!')
        subprocess.run('rm a*', shell=True)
        subprocess.run('rm out_*', shell=True)
        subprocess.run('rm diff_*', shell=True)
        return 0

def find_all(sub,s):
	index_list = []
	index = s.find(sub)
	while index != -1:
		index_list.append(index)
		index = s.find(sub,index+1)
	
	if len(index_list) > 0:
		return index_list
	else:
		return -1

def find_test_region(code):
    commit_list = list(commit_dict.keys())
    res_str = ''
    for gcc_commit in commit_list:
        print(gcc_commit)
        if not os.path.isdir(gcc_install_path + '/' + gcc_commit):
            gen_compiler(gcc_commit)
        gcc = gcc_install_path + '/' + gcc_commit + '/bin/gcc'
        res = evaluate(code, gcc)
        res_str += str(res)
    res_list = find_all('01', res_str)
    if res_list == -1:
        return [commit_list[-1], commit_list[-1], res_str]
    fail_index = res_list[-1]
    pass_index = fail_index + 1
    return [commit_list[fail_index], commit_list[pass_index], res_str]

def binary_find(code, branch):
    branch_file = 'gcc-log/log_' + branch + '.txt'
    if not os.path.exists(branch_file):
        log_branch = branch.replace('_', '.')
        cmd = 'git log origin/releases/gcc-' + log_branch + ' ^origin/master'
        subprocess.call(cmd, shell=True, cwd=git_home, stdout=open(branch_file, 'w'))
    commit_list = []
    end = branch_dict[branch][1]
    with open(branch_file, 'r') as branch_f:
        for line in branch_f.readlines():
            line = line.strip()
            if line == '':
                continue
            if 'commit' in line.split()[0]:
                commit_version = line.split()[-1].strip()
                commit = commit_version[:7]
                commit_list.append(commit)
                if commit == end:
                    break
    left = 0
    right = len(commit_list)
    commit_list.reverse()
    print('total length: ' + str(right))
    find_version = -1
    mid = int(left + right // 2)
    while left < right:
        gen_res = gen_compiler(commit_list[mid])
        if gen_res == -1:
            mid = mid + 1
            continue
        gcc = gcc_install_path + '/' + commit_list[mid] + '/bin/gcc'
        test_res = evaluate(code, gcc)
        if test_res == 1:
            print('test passed!')
            right = mid - 1
            find_version = commit_list[mid]
        else:
            print('test failed!')
            left = mid + 1
        mid = int((left + right) // 2)
    return find_version

def correct_commit(code):
    # failed_gcc = 'gcc-4.4.0'
    start_commit, end_commit, all_commit_str = find_test_region(code)
    passed_version = 'not find'
    if commit_dict[end_commit] != commit_dict[start_commit]:
        passed_version = end_commit
        print('find: ' + passed_version)
    elif start_commit != end_commit:
        passed_version = binary_find(code, commit_dict[start_commit])
        print('find: ' + passed_version)
    return passed_version

if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-i', '--gcc_install_path', type=str, default='', help='gcc install path')
    parser.add_option('-g', '--git_home', type=str, default='', help='gcc git home')
    parser.add_option('-p', '--gmp_home', type=str, default='', help='gmp home')
    parser.add_option('-r', '--mpfr_home', type=str, default='', help='mpfr home')
    parser.add_option('-c', '--mpc_home', type=str, default='', help='mpc home')
    parser.add_option('-b', '--bug_path', type=str, default='', help='bug path')

    (options, args) = parser.parse_args()

    gcc_install_path = options.gcc_install_path
    git_home = options.git_home
    gmp_home = options.gmp_home
    mpfr_home = options.mpfr_home
    mpc_home = options.mpc_home
    bug_path = options.bug_path

    passed_version = correct_commit(bug_path)
    print(passed_version)