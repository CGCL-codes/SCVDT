# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM hust-fuzz-base/base-llvm11
MAINTAINER yijun2238@gmail.com
#RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list
#RUN apt-get clean

RUN apt update
RUN apt install -y autoconf automake
RUN apt install -y python-dev python3 python3-dev python3-pip python-bs4
RUN apt install -y libtool-bin libboost-all-dev

RUN python3 -m pip install --upgrade pip
RUN python3 -m pip install networkx pydot pydotplus


# Default build flags for various sanitizers.
ENV SANITIZER_FLAGS_address "-fsanitize=address -fsanitize-address-use-after-scope"
ENV SANITIZER_FLAGS_undefined "-fsanitize=bool,array-bounds,float-divide-by-zero,function,integer-divide-by-zero,return,shift,signed-integer-overflow,vla-bound,vptr -fno-sanitize-recover=undefined"
ENV SANITIZER_FLAGS_memory "-fsanitize=memory -fsanitize-memory-track-origins"

# Default build flags for coverage.
ENV COVERAGE_FLAGS="-fsanitize-coverage=trace-pc-guard,trace-cmp"

# Workaround ASAN false positive: https://github.com/google/sanitizers/issues/647
ENV ASAN_OPTIONS="detect_odr_violation=0"

# Coverage flags for generating coverage reports.
ENV COVERAGE_FLAGS_coverage="-fsanitize-coverage=bb,no-prune,trace-pc-guard -O0"

# Default sanitizer and fuzzing engine to use.
ENV SANITIZER="address"
ENV FUZZING_ENGINE="aflgo"

# Path to fuzzing engine library.
ENV LIB_FUZZING_ENGINE="/usr/lib/libFuzzingEngine.a"

# TODO: remove after tpm2 catchup.
ENV FUZZER_LDFLAGS ""

WORKDIR $SRC


#RUN git clone https://gitee.com/onecoderMan/Fuzzer.git libfuzzer

COPY compile compile_aflgo /usr/local/bin/

RUN chmod +x /usr/local/bin/compile
RUN chmod +x /usr/local/bin/compile_aflgo

RUN /usr/local/bin/compile_aflgo
CMD ["compile"]

