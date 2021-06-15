cp /etc/apt/sources.list /etc/apt/sources.list.bak
sudo docker cp ./sources.list 2d:/etc/apt/
apt update
apt install wget bzip2 gcc git make graphviz libopenblas-dev liblapack-dev \
libatlas-base-dev libblas-dev libpq-dev python-matplotlib pkg-config libfreetype6-dev
cd /opt
wget https://downloads.python.org/pypy/pypy3.7-v7.3.3-linux64.tar.bz2
tar jxvf pypy3.7-v7.3.3-linux64.tar.bz2
mv pypy3.6-v7.3.1-linux64 /usr/lib/
export PATH=/usr/lib/pypy3.7-v7.3.3-linux64/bin:$PATH
pypy3 -m ensurepip
pypy3 -m pip install --upgrade pip

pypy3 -m pip install gevent --pre

pypy3 -m pip install angr
pypy3 -m pip install pwn
pypy3 -m pip install cstruct
pypy3 -m pip install termcolor
pypy3 -m pip install jinja2
pypy3 -m pip install graphviz
pypy3 -m pip install seaborn
pypy3 -m pip install numpy
pypy3 -m pip install wheel
pypy3 -m pip install matplotlib==3.1.3
pypy3 -m pip install pandas
pypy3 -m pip install seaborn
pypy3 -m pip install structlog
pypy3 -m pip install python-json-logger
pypy3 -m pip install ansi2html
pypy3 -m pip install six==1.15.0
