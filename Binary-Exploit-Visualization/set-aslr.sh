#!/bin/sh

if [ $# -ne 1 ]
then
    echo 'usage: ./set_aslr.sh on/off'
    exit 
fi

if [ "$1" = "off" ]
then
    sudo sh -c "echo 0 > /proc/sys/kernel/randomize_va_space"
    echo 'aslr disabled.'
    echo 'remember to turn on aslr later.'
elif [ "$1" = "on" ]
then
    sudo sh -c "echo 2 > /proc/sys/kernel/randomize_va_space"
    echo 'aslr enabled.'
else
    echo 'invalid argument'
    exit
fi
