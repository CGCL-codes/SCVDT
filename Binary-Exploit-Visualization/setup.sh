#!/bin/sh

# compile record program
gcc ./source/ptrace/ptrace.c -o  record_ptrace

# apt installs
sudo apt install -y graphviz libopenblas-dev liblapack-dev \
libatlas-base-dev libblas-dev libpq-dev python-matplotlib \
pkg-config libfreetype6-dev

# install pypy3 before next steps
pypy3 -m ensurepip
pypy3 -m pip install --upgrade pip
pypy3 -m pip install -r ./requirements.txt

# disable system's aslr
sh ./set-aslr.sh off

# apt-get install -y tk-dev
# apt-get install -y python3-tk
