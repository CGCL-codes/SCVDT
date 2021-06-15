sudo docker run -e LC_CTYPE=C.UTF-8 -it --name workstation ubuntu:16.04 bash
cp /etc/apt/sources.list /etc/apt/sources.list.bak
sudo docker cp ./sources.list d2:/etc/apt/
apt update
apt-get install software-properties-common
add-apt-repository ppa:deadsnakes/ppa
apt update
apt upgrade

apt-get install python2.7 python-pip python-dev git libssl-dev libffi-dev build-essential vim gdb python3.6
apt-get -y install netcat-traditional 
python -m pip install --upgrade "pip<21.0"
python -m pip install pwntools
sudo docker cp ./get-pip.py 89:/opt/
python3 get-pip.py
python3 -m pip install --upgrade "pip<21.0"
python3 -m pip install unicorn
python3 -m pip install capstone
python3 -m pip install keystone-engine
python3 -m pip install ropper
sudo docker cp .gdbinit-gef.py 89:/root/
echo source ~/.gdbinit-gef.py >> ~/.gdbinit
echo export LC_CTYPE=C.UTF-8 >> ~/.bashrc

#ffmpeg demo
sudo docker run --privileged -e LC_CTYPE=C.UTF-8 -it --name ffmpeg_demo floating/workstation:1604 bash
