import random
import socket
from urllib import request
from urllib import error
from bs4 import BeautifulSoup

from common.config import LOG_DIR
from common.io import write_log
from common.models import Exploit

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


def spider(spider_url):
    user_agent = random.choice(ua_list)
    spider_request = request.Request(spider_url)
    spider_request.add_header('User-Agent', user_agent)
    try:
        spider_response = request.urlopen(spider_request, timeout=30)
    except socket.timeout as e:
        return 'error, socket.timeout'
    except error.URLError as e:
        return 'error, URLError'

    # noinspection PyBroadException
    try:
        spider_html = spider_response.read().decode('utf-8')
    except socket.timeout as e:
        return 'error, socket.timeout'
    except UnicodeDecodeError as e:
        return 'error, UnicodeDecodeError'
    except Exception as e:
        return 'error, Exception: %s' % e

    return spider_html


def cwe_bs4_html(cwe, bs4_html):
    # 实现对html的解析
    soup = BeautifulSoup(bs4_html, 'html.parser')
    data = []
    try:
        data.append(cwe)
        h2 = soup.find('h2')
        length = len(cwe) + 2
        title = h2.get_text()[length:]
        # print(title)
        data.append(title)
    except Exception as e:
        f = r'{0}\cwe-error.txt'.format(LOG_DIR)
        write_log(f, cwe + ' ' + 'error, Parse')
    return data


def get_item(line, exploit):
    pos = line.find(':')
    if line[:pos] == 'EDB-ID':
        exploit.setEid(int(line[pos + 1:]))
    elif line[:pos] == 'CVE':
        exploit.setCVE('CVE-' + line[pos + 1:])
    # else:
    #     print(line)


def exploit_bs4_html(bs4_html):
    soup = BeautifulSoup(bs4_html, 'html.parser')
    try:
        exploit = Exploit(soup.title.text)
    except AttributeError as e:
        return Exploit('error, AttributeError')
    for div in soup.find_all('div', class_='col-sm-12 col-md-6 col-lg-3 d-flex align-items-stretch'):
        for h in div.find_all('div', class_='col-6 text-center'):
            get_item(h.h4.get_text().strip() + h.h6.get_text().strip(), exploit)
    return exploit
