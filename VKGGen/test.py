import time
import re
import pandas as pd

from common.config import BASE_DIR

if __name__ == '__main__':
    # time_now = time.strftime('%Y-%m-%d %H:%M:%S')
    # print('[INFO] CWE-22' + '\t' + 'error, URLError' + '\t' + time_now)
    # pattern = re.compile('^[_a-zA-Z][_a-zA-Z0-9(->)?(\.)?]*$')
    # print(re.findall(pattern, 'a->c.x'))
    diff_excel = r'{0}/java_diff数据汇总.xlsx'.format(BASE_DIR)
    dataFrame = pd.read_excel(diff_excel)
    software_dict = dict()
    for index, data in dataFrame.iterrows():
        software = data['软件名']
        if software not in software_dict.keys():
            software_dict[software] = set()
        cve_id = data['CVE号']
        software_dict[software].add(cve_id)
    for (k, v) in software_dict.items():
        print(k + '\t' + str(len(v)))
