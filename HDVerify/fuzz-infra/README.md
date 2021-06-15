# FuzzInfra
This project is based on the open-source project [oss-fuzz](https://github.com/google/oss-fuzz.git). It is mainly to provide some container environment for software to fuzzing


# Description
there are four docker images for building directed grey-box fuzzing<br>

*  **base-image18** It is the basic image, providing ubuntu18.04 operating system

* **base-llvm11** It provides [llvm-11](https://releases.llvm.org/11.0.1/docs/ReleaseNotes.html) compilation chain tool

* **base-buildfast** It provides modified AFLGo, which can be used for instrumentation and static analysis of the target program

* **base-runner3** It is used to run the fuzzing loop

# Environment
Ubuntu 16.04 64bit
Docker

# Construction 
Run the `all.sh` script to build these images

For base-llvm11, we can use the command to build
```
docker pull registry.cn-qingdao.aliyuncs.com/hust_image/base-llvm11:v1-llvm11
docker tag  eeec8d6e4532 hust-fuzz-base/base-llvm11:latest
```



