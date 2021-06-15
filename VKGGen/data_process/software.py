import locale
import pandas as pd

from common.config import DEPENDENCY_DIR, LOG_DIR
from common.io import write_log
from fake_useragent import UserAgent
import requests
from bs4 import BeautifulSoup
import os
import random
import traceback

from common.models import Software
from graph_process.database import query_software_cve_num

ua_list = ["Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/22.0.1207.1 Safari/537.1",
           "Mozilla/5.0 (X11; CrOS i686 2268.111.0) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 "
           "Safari/536.11",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
           "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1090.0 Safari/536.6",
           "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/19.77.34.5 Safari/537.1",
           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
           "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.36 Safari/536.5",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
           "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 Safari/536.3",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_8_0) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1063.0 "
           "Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1062.0 Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
           "Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.0 Safari/536.3",
           "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24",
           "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/535.24 (KHTML, like Gecko) Chrome/19.0.1055.1 Safari/535.24"
           ]

'''
下载pom.xml文件
1. 从SVN仓库下载
2.从github仓库下载
'''


def run_download():
    softwares = ['struts', 'ofbiz', 'cxf', 'activemq', 'nifi', 'camel', 'hadoop', 'geronimo', 'tika', 'geode',
                 'cloudstack', 'hive', 'poi', 'jspwiki', 'pivot', 'openmeetings', 'storm', 'ambari', 'spark', 'ranger',
                 'wicket', 'thrift', 'accumulo', 'airavata', 'archiva', 'aries', 'asterixdb', 'atlas', 'avro', 'bigtop',
                 'bookkeeper', 'bval', 'calcite', 'cayenne', 'chukwa', 'clerezza', 'cocoon', 'continuum',
                 'creadur-rat', 'ctakes', 'curator']
    # softwares = ['pivot']
    # for software in softwares:
    #     download_from_svn(software)
    #     download_from_github(software, 'apache')
    apache_commons_software = ['commons-bcel', 'commons-beanutils', 'commons-bsf', 'commons-chain', 'commons-cli',
                               'commons-codec', 'commons-collections', 'commons-compress', 'commons-crypto',
                               'commons-csv', 'commons-dbcp', 'commons-dbutils', 'commons-digester', 'commons-email',
                               'commons-exec', 'commons-fileupload', 'commons-functor', 'commons-geometry',
                               'commons-graph', 'commons-imaging', 'commons-io', 'commons-jci', 'commons-jcs',
                               'commons-jelly', 'commons-jexl', 'commons-jxpath', 'commons-lang', 'commons-logging',
                               'commons-math', 'commons-net', 'commons-numbers', 'commons-pool', 'commons-proxy',
                               'commons-rdf', 'commons-release-plugin', 'commons-rng', 'commons-scxml', 'commons-text',
                               'commons-validator', 'commons-vfs', 'commons-weaver']
    # for software in apache_commons_software:
    #     download_from_github(software, 'apache')
    software_file = r'{0}/{1}'.format(DEPENDENCY_DIR, 'apache的Java软件按CVE排序.txt')
    f = open(software_file, 'r')
    for item in f.readlines():
        data = item.split()
        software = data[0]
        if software not in softwares and software not in apache_commons_software:
            download_from_svn(software)
            download_from_github(software, 'apache')


def preprocess():
    excel_file = r'{0}/{1}'.format(DEPENDENCY_DIR, 'apache所有Java软件.xlsx')
    dataframe = pd.read_excel(excel_file)
    softwares = {}
    for index, data in dataframe.iterrows():
        software = data['软件名']
        update_time = data['更新日期']
        stars = data['star']
        # if int(stars) < 50:
        #     break
        # 查找软件对应的CVE总数
        # cve_nums = query_software_cve_num(software)[0]['count(n.cve_id)']
        # print(software + '\t' + update_time[-4:] + '\t' + str(stars) + '\t' + str(cve_nums))
        cve_nums = data['CVE数量']
        if int(cve_nums) > 0:
            softwares[software] = int(cve_nums)
    software_list = sorted(softwares.items(), key=lambda item: item[1], reverse=True)
    for item in software_list:
        print(item[0] + '\t' + str(item[1]))


def download_from_svn(software):
    headers = {
        'User-Agent': random.choice(ua_list)
    }
    url = 'https://svn.apache.org/repos/asf/' + software
    print('[+] Download {0} POM from svn.'.format(software))
    getstr = requests.get(url=url, headers=headers).content.decode("utf-8")
    if '<title>404 Not Found</title>' in getstr:
        log_file = r'{0}/download_pom_log.txt'.format(LOG_DIR)
        log_info = '{0} software not exists in svn repository.'.format(software)
        write_log(log_file, log_info)
        return
    filePath = r'{0}'.format(DEPENDENCY_DIR)
    os.chdir(filePath)
    if not os.path.exists(software):
        os.mkdir(software)
    os.chdir(software)
    soup = BeautifulSoup(getstr, 'html5lib')
    ul = soup.find('ul')
    cnt = 0
    flag = False
    for li in ul.find_all('li'):
        a = li.find('a')
        if a.text == 'trunk/':
            trunk_url = url + '/' + a.get('href')
            output_file = '{0}.xml'.format(a.text[:-1])
            # print(output_file)
            if os.path.exists(output_file):
                continue
            temp = write_pom_from_svn(trunk_url, output_file)
            flag = True if flag else temp
        elif a.text == 'tags/':
            tags_url = url + '/' + a.get('href')
            tags_html = requests.get(url=tags_url, headers=headers).content.decode("utf-8")
            tags_soup = BeautifulSoup(tags_html, 'html5lib')
            tags_ul = tags_soup.find('ul')
            for tags_li in tags_ul.find_all('li'):
                tags_li_a = tags_li.find('a')
                if tags_li_a.text == '..':
                    continue
                else:
                    tags_li_url = tags_url + '/' + tags_li_a.get('href')
                    output_file = '{0}.xml'.format(tags_li_a.text[:-1])
                    print(output_file)
                    if os.path.exists(output_file):
                        continue
                    temp = write_pom_from_svn(tags_li_url, output_file)
                    flag = True if flag else temp
    if not flag:
        log_file = r'{0}/download_pom_log.txt'.format(LOG_DIR)
        info = '{0} not exist tags.'.format(software)
        write_log(log_file, info)
    print('Successfully finished download the {0} POM'.format(software))
    # os.chdir(r'D:\学习\研究生\攻防自动化\漏洞数据库\Java漏洞数据\dependencies\{0}\pom({1}).xml'.format(software))
    # file = open(r'pom_test.xml', 'a')
    # file.write(getstr.encode('GBK', 'ignore').decode('GBK').encode('ascii', 'ignore').decode('ascii'))
    # file.close()


def write_pom_from_svn(url, output_file):
    headers = {
        'User-Agent': random.choice(ua_list)
    }
    getstr = requests.get(url=url, headers=headers).content.decode("utf-8")
    soup = BeautifulSoup(getstr, 'html5lib')
    ul = soup.find('ul')
    if ul is None:
        return False
    for li in ul.find_all('li'):
        a = li.find('a')
        if a.text == 'pom.xml':
            pom_url = url + '/' + a.get('href')
            getstr = requests.get(url=pom_url, headers=headers).content.decode("utf-8")
            file = open(output_file, 'a')
            file.write(getstr.encode('GBK', 'ignore').decode('GBK').encode('ascii', 'ignore').decode('ascii'))
            file.close()
            return True
    return False


def process_github(url, software, software_branch):
    # headers = {
    #     'User-Agent': UserAgent(verify_ssl=False).random
    # }
    headers = {
        'User-Agent': random.choice(ua_list)
    }
    proxies = {
        'https': 'https://216.155.135.209:2233'
    }
    diction = {}
    try:
        getstr = requests.get(url=url, headers=headers).content.decode("utf-8")
        soup = BeautifulSoup(getstr, 'html5lib')
        div = soup.find('div', class_='js-details-container Details')
        div1 = div.find('div',
                        class_='Details-content--hidden-not-important js-navigation-container js-active-navigation-container d-md-block')
        flag = False
        for part_div in div1.find_all('div',
                                      class_='Box-row Box-row--focus-gray py-2 d-flex position-relative js-navigation-item'):
            if flag:
                break
            links = part_div.find_all('a')
            for link in links:
                if link.get('title') == 'pom.xml':
                    href = link.get('href').replace('/blob', '')
                    url = 'https://raw.githubusercontent.com' + href
                    print(url)
                    getstr = requests.get(url=url, headers=headers
                                          ).content.decode("utf-8")
                    write_plain_file(getstr, software, software_branch)
                    flag = True
                    break
    except Exception as e:
        log_file = r'{0}/download_pom_log.txt'.format(LOG_DIR)
        info = 'Parse url: {0} error.'.format(url)
        write_log(log_file, info)
        f = open(r'{0}/errors.log'.format(LOG_DIR), 'a')
        print('----------------------------------------', file=f)
        print(e, file=f)
        traceback.print_exc(file=f)
        print('----------------------------------------', file=f)
        f.close()


def write_plain_file(getstr, software, software_branch):
    os.chdir(r'{0}'.format(DEPENDENCY_DIR))
    if not os.path.exists(software):
        os.mkdir(software)
    os.chdir(software)
    # 注意
    if '/' in software_branch:
        file = open(r'{0}.xml'.format(software_branch.replace('/', '_')), 'a')
    else:
        file = open(r'{0}.xml'.format(software_branch), 'a')
    file.write(getstr.encode('GBK', 'ignore').decode('GBK').encode('ascii', 'ignore').decode('ascii'))
    file.close()


def download_from_github(software, vendor):
    headers = {
        'User-Agent': random.choice(ua_list)
    }
    print('[+] Download {0}/{1} POM from github.'.format(vendor, software))
    tag_url = 'https://github.com/{0}/{1}/tags'.format(vendor, software)
    flag = True
    while flag:
        getstr = requests.get(url=tag_url, headers=headers).content.decode("utf-8")
        soup = BeautifulSoup(getstr, 'html5lib')
        div = soup.find('div', class_='repository-content')
        if div is None:
            print("[INFO] {0} doesn't have tags.".format(tag_url))
            break
        div1 = div.find('div', class_='Box')
        if div1 is None:
            print("[INFO] {0} doesn't have tags.".format(tag_url))
            break
        for part_div in div1.find_all('div', class_='commit js-details-container Details'):
            links = part_div.find_all('a')
            for link in links:
                if 'releases' in link.get('href'):
                    software_branch = link.getText().strip()
                    # print(software_branch)
                    software_dir = r'{0}/{1}'.format(DEPENDENCY_DIR, software)
                    if not os.path.exists(software_dir):
                        os.mkdir(software_dir)
                    poms = os.listdir(software_dir)
                    if r'{0}.xml'.format(software_branch) in poms:
                        # print(software_branch)
                        continue
                    software_github = 'https://github.com/{0}/{1}/tree/{2}'.format(vendor, software, software_branch)
                    print(software_github)
                    process_github(software_github, software, software_branch)
        div = soup.find('div', class_='paginate-container')
        links = div.find_all('a')
        f = False
        for link in links:
            if link.getText().strip() == 'Next':
                tag_url = link.get('href')
                f = True
        flag = f
    print('Successfully finished download the {0}/{1} POM'.format(vendor, software))


# 获取github上apache的所有java软件信息
def get_apache_software():
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    headers = {
        'User-Agent': random.choice(ua_list)
    }
    url = 'https://github.com/apache?q=&type=&language=java&sort=name'
    softwares = []
    while True:
        getstr = requests.get(url=url, headers=headers).content.decode("utf-8")
        if '<title>404 Not Found</title>' in getstr:
            print('[INFO] URL error.')
            return
        print(url)
        soup = BeautifulSoup(getstr, 'html5lib')
        div = soup.find('div', class_='org-repos repo-list')
        ul = div.find('ul')
        for li in ul.find_all('li'):
            software = Software()
            h3 = li.find('h3')
            name = h3.find('a').text.strip()
            p = li.find('p', class_='break-word text-gray mb-0')
            description = 'None'
            if p is not None:
                description = p.text.strip()
            div1 = li.find('div', class_='text-gray f6 mt-2')
            span = div1.find('span', class_='no-wrap')
            update_time = span.text.strip()
            software.setVendor('apache')
            software.setSoftwareName(name)
            software.setDescription(description)
            software.setLanguage('java')
            software.setUpdateTime(update_time)
            software.setUrl('https://github.com/apache/' + name)
            fork_links = div1.find_all('a', class_='muted-link mr-3')
            for fork_link in fork_links:
                fork_svg = fork_link.find('svg', class_='octicon octicon-repo-forked')
                if fork_svg is not None:
                    fork = locale.atoi(fork_link.text.strip())
                    software.setFork(fork)
            star_a = div1.find('a', class_='no-wrap muted-link mr-3')
            if star_a is not None:
                star = locale.atoi(star_a.text.strip())
                software.setStar(star)
            softwares.append(software)
        div = soup.find('div', class_='pagination')
        next = div.find('a', class_='next_page')
        if next is None:
            break
        url = 'https://github.com' + next.get('href')
    for software in softwares:
        print(software)


'''
删除空白文件夹
注：有的软件没有pom.xml文件
'''


def delete_blank_directory():
    os.chdir(DEPENDENCY_DIR)
    for dir in os.listdir(DEPENDENCY_DIR):
        if os.path.isdir(dir):
            if len(os.listdir(dir)) == 0:
                file = open('info.txt', 'a')
                file.write('{0} software does not have poms.\n'.format(dir))
                file.close()
                os.removedirs(dir)


if __name__ == '__main__':
    # process_github('https://github.com/jenkinsci/jenkins')
    # parsePom(r'C:\Users\37537\Desktop\pom.xml')
    # download_from_svn('activemq')
    # run_download()
    # process_github('https://github.com/apache/jspwiki/tree/2.11.0.M8')
    # download_from_github()
    # delete_blank_directory()
    run_download()
    # get_apache_software()
    # preprocess()