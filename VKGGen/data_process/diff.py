import os
import pandas as pd
from common.config import DIFF_DIR, BASE_DIR, LOG_DIR
from common.io import write_log
from common.models import Diff
from graph_process.database import add_diff, query_vulnerability, add_relation, query_software_version_by_cs

def add_c_diff_to_graph():
    diff_excel = '{0}/C-diff汇总.xlsx'.format(BASE_DIR)
    dataFrame = pd.read_excel(diff_excel)
    for index, data in dataFrame.iterrows():
        diff = Diff()
        software = data['软件名']
        cve_id = data['CVE号']
        diff_url = data['diff_url']
        if type(diff_url) is not str:
            diff_url = 'null'
        diff_file = data['文件名']
        print('[+] add diff file: {0} to knowledge graph.'.format(diff_file))
        diff_file = r'{0}/{1}/{2}/{3}'.format('/root/work/Program/diffs', software.replace(':', '+'), cve_id, diff_file)
        # print(cve_id, diff_url, diff_file)
        diff.setUrl(diff_url)
        diff.setCVE(cve_id)
        diff.setSoftware(software)
        diff.setDiffFile(diff_file)
        diff.setLanguage('c/c++')
        # print(diff)
        diff_node = add_diff(diff)
        node = query_vulnerability(cve_id)
        if node is None or len(node) == 0:
            log_file = r'{0}/diff-log.txt'.format(LOG_DIR)
            write_log(log_file, '{0} not exist in graph.'.format(cve_id))
            continue
        vuln_node = node[0]['a']
        add_relation(vuln_node, 'has', diff_node)
        software_name = software.split(':')[-1]
        nodes = query_software_version_by_cs(cve_id, software_name)
        if nodes is None or len(nodes) == 0:
            log_file = r'{0}/diff-log.txt'.format(LOG_DIR)
            write_log(log_file, '{0} not exist software {1} in graph.'.format(cve_id, software_name))
            continue
        for node in nodes:
            add_relation(diff_node, 'belong to', node['n'])
        print('successfully finished.')


def add_java_diff_to_graph():
    diff_excel = '{0}/java_diff数据汇总.xlsx'.format(BASE_DIR)
    dataFrame = pd.read_excel(diff_excel)
    extra = {'jenkins:Jenkins': 'jenkinsci:jenkins', 'owncloud:owncloud': 'owncloud',
             'apache:sling-org-apache-sling-xss': 'apache:sling-org-apache-sling-xss'}
    for index, data in dataFrame.iterrows():
        diff = Diff()
        software = data['软件名']
        if software in extra.keys():
            software = extra[software]
        cve_id = data['CVE号']
        diff_url = data['diff_url']
        diff_file = data['文件名']
        print('[+] add diff file: {0} to knowledge graph.'.format(diff_file))
        diff_file = r'{0}/{1}/{2}/{3}'.format(DIFF_DIR, software.replace(':', '+'), cve_id, diff_file)
        # print(cve_id, diff_url, diff_file)
        diff.setUrl(diff_url)
        diff.setCVE(cve_id)
        diff.setSoftware(software)
        diff.setDiffFile(diff_file)
        diff.setLanguage('java')
        diff_node = add_diff(diff)
        node = query_vulnerability(cve_id)
        if node is None or len(node) == 0:
            log_file = r'{0}/diff-log.txt'.format(LOG_DIR)
            write_log(log_file, '{0} not exist in graph.'.format(cve_id))
            continue
        vuln_node = node[0]['a']
        add_relation(vuln_node, 'has', diff_node)
        software_name = software.split(':')[-1]
        nodes = query_software_version_by_cs(cve_id, software_name)
        if nodes is None or len(nodes) == 0:
            log_file = r'{0}/diff-log.txt'.format(LOG_DIR)
            write_log(log_file, '{0} not exist software {1} in graph.'.format(cve_id, software_name))
            continue
        for node in nodes:
            add_relation(diff_node, 'belong to', node['n'])
        print('successfully finished.')


# def test():
#     dir_path = r'D:\学习\研究生\毕业设计\data\diffs'
#     os.chdir(dir_path)
#     dir_softwares = set()
#     for dir in os.listdir(dir_path):
#         dir_softwares.add(dir)
#     path = r'D:\学习\研究生\毕业设计\diff数据汇总.xlsx'
#     dataFrame = pd.read_excel(path)
#     software_cves = {}
#     softwares = []
#     for index, data in dataFrame.iterrows():
#         software = data['软件名']
#         cve_id = data['CVE号']
#         diff_url = data['diff_url']
#         file_name = data['文件名']
#         # if software in dir_softwares:
#         #     file_path = '{0}/{1}/{2}/{3}'.format(DIFF_DIR, software, cve_id, file_name)
#         #     print('\t'.join([software, cve_id, diff_url, file_path]))
#         if 'apache' in software and software.split(':')[-1] not in softwares:
#             softwares.append(software.split(':')[-1])
#         if software.split(':')[-1] not in software_cves:
#             software_cves[software.split(':')[-1]] = set()
#         software_cves[software.split(':')[-1]].add(cve_id)
#     # for software in softwares:
#     #     print(software)
#     for (k, v) in software_cves.items():
#         software_cves[k] = len(v)
#     temp = sorted(software_cves.items(), key=lambda x: x[1], reverse=True)
#     for (k, v) in temp:
#         print(k + '\t' + str(v))


if __name__ == '__main__':
    # test()
    add_java_diff_to_graph()
    add_c_diff_to_graph()
