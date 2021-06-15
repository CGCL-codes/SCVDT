#!/usr/bin/python3

# FIXME: now this file should be placed at root folder od the project!
# fix the path later
"""
Use socat to bind target program to a port, like deploying a pwn challenge in ctf.

It first generates a temp script，in which the log file and mmap dump's hook is set, 
then use the script as socat's argument.

By using this stage, we don't need to modify the original writeup.
"""
import os
import sys
from hashlib import md5
from random import randint
import subprocess

def usage():
    print("Usage: " + __file__ + " port-to-bind path-to-target [args]")


def gen_target_script(target, args = ""):
    fname = target + str(randint(0, 1<<10))
    fname = md5(fname.encode(encoding='UTF-8')).hexdigest()[:12]
    fname = '/tmp/'+fname
    with open(fname, 'w') as f:
        f.write("#!/bin/sh\n")
        f.write("./bin/tee record.%s.%s | LD_PRELOAD=./bin/mmap_dump.so %s " %(target.split("/")[-1], fname[-4:],target))
        if args:
            f.write(" ".join(args))
        f.write("\n")
    os.system("chmod +x " + fname)
    print("Generated temp script %s\n" % (fname))
    print("Logged input will be written to record.%s.%s\n"% (target.split("/")[-1], fname[-4:]))
    return fname

def rm_temp_file(fname):
    os.system("rm "+ fname)

def socket_bind(port, fname):
    print("Start port bind.")
    cmd = "socat tcp-l:%d, exec:'%s'" % (port, fname)
    p = subprocess.Popen(["/bin/sh", "-c", cmd])
    p.wait()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
        exit(0)
    else:
        port = int(sys.argv[1])
        target = sys.argv[2]
        args = ""

        if len(sys.argv) > 3:
            args = sys.argv[3:]

        fname = gen_target_script(target, args)
        socket_bind(port, fname)
        rm_temp_file(fname)
        