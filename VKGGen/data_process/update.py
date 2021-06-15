import urllib

import pymysql
import requests
import os

from common.config import NVD_FEEDS_DIR, UNZIP_BINARY, LOG_DIR, EXPLOIT_DIR

# 下载NVD更新文件，每7天更新一次
from common.io import write_log
from data_process.crawl import spider, cwe_bs4_html, exploit_bs4_html
from data_process.exploit import download_exploit, add_to_mysql, add_to_graph
from data_process.vulnerability import parse_nvd
from graph_process.database import query_cwe_description_null, set_cwe_description


def download_nvd_modified():
    url = 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip'
    # 下载文件存放路径
    download_path = r'{0}\nvdcve-1.1-modified.json.zip'.format(NVD_FEEDS_DIR)
    urllib.request.urlretrieve(url, download_path)


def update_nvd():
    download_nvd_modified()
    zip_path = r'{0}\nvdcve-1.1-modified.json.zip'.format(NVD_FEEDS_DIR)
    modified_path = r'{0}\nvdcve-1.1-modified.json'.format(NVD_FEEDS_DIR)
    if os.path.exists(modified_path):
        os.remove(modified_path)
    command_line = r'{0} {1} -d {2}'.format(UNZIP_BINARY, zip_path, NVD_FEEDS_DIR)
    os.system(command_line)
    parse_nvd(modified_path)
    os.remove(zip_path)


def update_cwe_description():
    nodes = query_cwe_description_null()
    for node in nodes:
        cwe_id = node['cwe_id']
        print(cwe_id)
        # 从cwe官网获取漏洞类型描述信息
        url = "https://cwe.mitre.org/data/definitions/{0}.html".format(cwe_id.split('-')[-1])
        html = spider(url)
        if html[0:5] == 'error':
            f = r'{0}\cwe-error.txt'.format(LOG_DIR)
            write_log(f, cwe_id + ' ' + html)
            continue
        data = cwe_bs4_html(cwe_id, html)
        if len(data) != 2:
            continue
        description = data[1]
        # print(cwe_id, description)
        set_cwe_description(cwe_id, description)


# 需手动设置一下最后的eid号
def update_exploit(num):
    connection = pymysql.connect(host='127.0.0.1', user='root', passwd='123456', port=3306, db='test',
                                 charset='utf8')
    cursor = connection.cursor()
    sql = "select ID, EDB_ID from exploit_graph order by id desc limit 1"
    cursor.execute(sql)
    results = cursor.fetchall()
    id = int(results[0][0])
    start = int(results[0][1])
    urlbase = 'https://www.exploit-db.com/exploits/'
    for i in range(start+1, num+1):
        url = urlbase + str(i) + '/'
        print('[+]' + url)
        html = spider(url)
        if html[0:5] == 'error':
            file = r'{0}/exploit-log.txt'.format(LOG_DIR)
            info = str(i) + ' ' + html
            write_log(file, info)
            continue
        exploit = exploit_bs4_html(html)
        if exploit.eid == 0 or len(exploit.cve_id.split('-')) != 3:
            continue
        exploit.setUrl('https://www.exploit-db.com/exploits/' + str(i))
        file_name = download_exploit(exploit.cve_id, exploit.eid)
        exploit.setCodeFile(r'{0}\{1}\{2}'.format(EXPLOIT_DIR, exploit.cve_id, file_name))
        try:
            add_to_mysql(exploit)
        except Exception as e:
            file = r'{0}/exploit-log.txt'.format(LOG_DIR)
            info = str(i) + ' ' + 'error, Unknow'
            write_log(file, info)
            continue
        print(url + ' OK ')
    add_to_graph(id+1)


def update_graph():
    update_nvd()
    update_cwe_description()
    update_exploit(0)


if __name__ == '__main__':
    # update_nvd()
    # update_cwe_description()
    # update_exploit(0)
    update_graph()
