#!/bin/bash -eux

#定向模糊测试的环境
docker build -t  hust-fuzz-base/base-image18 "$@" base-image18
docker build -t hust-fuzz-base/base-llvm11 "$@" base-llvm11
docker build -t hust-fuzz-base/base-fastbuilder "$@" base-builderfast
docker build -t hust-fuzz-base/base-runner3 "$@" base-runner3

