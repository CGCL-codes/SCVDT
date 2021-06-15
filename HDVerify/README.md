# HDVerify
A vulnerability verification system that can verify suspicious vulnerabilities in C/C++ open-source software obtained by static tools based on improved directed grey-box fuzzing.

For suspicious vulnerabilities, the system is dedicated to finding the input that triggers the vulnerability.

The inputs of the system are the code of open-source software, the compilation script, the location of the suspicious vulnerability(filename:line).

The outputs are all crash cases and a cases that trigger suspicious vulnerabilities.

# Setup
* install fuzz-infra
Execute the installation script of fuzz-infra(`fuzz-infra/all.sh`)
```
root@Coder:~# docker images
REPOSITORY                                                TAG                 IMAGE ID            CREATED             SIZE
hust-fuzz-base/base-fastbuilder                           latest              0710c392611c        5 weeks ago         6.13GB
hust-fuzz-base/base-runner3                               latest              cb798ce85873        5 weeks ago         6.13GB
hust-fuzz-base/base-llvm11                                latest              eeec8d6e4532        8 weeks ago         6.13GB
hust-fuzz-base/base-image18                               latest              023ad7167520        8 weeks ago         99.9MB
```

Once the build has been successful, lunch the Docker image to test out base-fastbuilder.
```
$ docker run -it hust-fuzz-base/base-fastbuilder /bin/bash
```

* install Python2.7
```
root@Coder:~# python -V
Python 2.7.12
```


# Usage

## prepare the software
upload the software to the [github](https://github.com/) or [gitee](https://gitee.com/)<br>
eg:`https://gitee.com/onecoderMan/jasper.git`
<br>
## init the work
create a new folder named `projects`,then create three files in projects folder.

* the first one is `build.sh` whose content is as follows
```
export LDFLAGS=-lpthread
./configure --disable-shared
make clean
make

cp ./src/appl/jasper $OUT/
```

> All commands for software compilation are placed here. For different software, **cp XXX $OUT/** is fixed, just need to change the path where the program is located.

* the second one is Dockerfile whose content is as follows
```
FROM hust-fuzz-base/base-fastbuilder

RUN apt-get install -y build-essential

RUN git clone https://gitee.com/onecoderMan/jasper.git

WORKDIR jasper

COPY build.sh $SRC/
COPY BBtargets.txt $SRC/
```

> For different software, `FROM hust-fuzz-base/base-fastbuilder` is fixed, the second line place the dependence, the third line just change the software site from github/gitlee; `WORKDIR` is fixed, just change the home directory of the software; `COPY build.sh $SRC/` and `COPY BBtargets.txt $SRC/` are fixed.

* the third one is BBtargets.txt whose content is as follows
```
src/libjasper/mif/mif_cod.c:558
src/libjasper/mif/mif_cod.c:555
```

place the location of the suspicious vulnerability here(`fileName:line`)

## Compilation and instrumentation
* Make folders
```
mkdir build
mkdir build/work
mkdir build/out
```

* build images
```
docker  build  -t  id0000  projects
```
Following `-t` is image's name

* compile
```
docker run --rm  --cap-add SYS_PTRACE \
-e FUZZING_ENGINE=aflgo  \
-e SOURCE_DIR=./src/appl/ \
-e FUZZER=jasper \
-v build/out:/out \
-v build/work:/work \
-t id0000  compile
```
`SOURCE_DIR` is followed by the directory path where the binary program is located.
`FUZZER` is the binary program.

## run

* set core_pattern
```
echo core >/proc/sys/kernel/core_pattern
```

* launch
```
docker run --rm  --cap-add SYS_PTRACE   \
-e PROCESSID=id0000 \
-v build/out:/work \
-v build/out/fuzzer_dir:/out  \
-v projects/in:/in \
-t hust-fuzz-base/base-runner3 run_fuzzer  \
jasper -f @@ -t mif -F /tmp/out -T jpg
```
`PROCESSID` is only a flag which can be used to stop process, the last line is command to run the program.

## stop
```
pkill afl
```
or
```
ps aux | grep id0000
kill -9 [pid]
```

## analysis crash
```
python crash-verify/run_verify.py \
-t "build/out/noinstrument/jasper -f @@ -t mif -F /tmp/out -T jpg" \
-d build/out  \
-i build/fuzzer_dir/crashes \
-b symfile
```


