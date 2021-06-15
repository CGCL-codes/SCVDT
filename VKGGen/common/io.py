import time


def write_log(file, info):
    f = open(file, 'a')
    time_now = time.strftime('%Y-%m-%d %H:%M:%S')
    print('[INFO] {0}\t{1}'.format(info, time_now), file=f)
    f.close()
