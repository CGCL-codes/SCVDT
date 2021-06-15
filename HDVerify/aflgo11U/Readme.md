# AFLGo11U
This project is based on the open-source project [AFLGo](https://github.com/aflgo/aflgo) from **cf5c7ab** commits. 

we improve the directed grey-box fuzzing so that it can be used to achieve vulnerability verification. 
* For seed selection, we not only consider the distance but also include the times of seed executions and the ability to explore seed paths into the consideration of seed selection. 

* In terms of seed mutation strategy, we introduce distance-guided mutation which can protect the key byte of the seed from damage and can guide the seed to the target code area. We then divide the mutation strategies into different granularities and apply different mutations to the seed depending on the distance of the seed. 

* In order to coordinate the two phases of exploration and exploitation, we propose a dynamic strategy to split the two phases. 

* To generate inputs whose execution path is guarded by complex or tight constraints, we introduce concolic execution to help the directed grey-box fuzzing to explore more paths. 

# AFLGo: Directed Greybox Fuzzing
<a href="https://mboehme.github.io/paper/CCS17.pdf" target="_blank"><img src="https://github.com/mboehme/mboehme.github.io/blob/master/paper/CCS17.png" align="right" width="250"></a>
AFLGo is an extension of <a href="https://lcamtuf.coredump.cx/afl/" target="_blank">American Fuzzy Lop (AFL)</a>.
Given a set of target locations (e.g., `folder/file.c:582`), AFLGo generates inputs specifically with the objective to exercise these target locations.

Unlike AFL, AFLGo spends most of its time budget on reaching specific target locations without wasting resources stressing unrelated program components. This is particularly interesting in the context of
* **patch testing** by setting changed statements as targets. When a critical component is changed, we would like to check whether this introduced any vulnerabilities. AFLGo, a fuzzer that can focus on those changes, has a higher chance of exposing the regression.
* **static analysis report verification** by setting statements as targets that a static analysis reports as potentially dangerous or vulnerability-inducing. When assessing the security of a program, static analysis tools might identify dangerous locations, such as critical system calls. AFLGo can generate inputs that actually show that this is indeed no false positive.
* **information flow detection** by setting sensitive sources and sinks as targets. To expose data leakage vulnerabilities, a security researcher would like to generate executions that exercise sensitive sources containing private information and sensitive sinks where data becomes visible to the outside world. A directed fuzzer can be used to generate such executions efficiently.
* **crash reproduction**  by setting method calls in the stack-trace as targets. When in-field crashes are reported, only the stack-trace and some environmental parameters are sent to the in-house development team. To preserve the user's privacy, the specific crashing input is often not available. AFLGo could help the in-house team to swiftly reproduce these crashes.

AFLGo is based on <a href="http://lcamtuf.coredump.cx/afl/" target="_blank">AFL</a> from Michał Zaleski \<lcamtuf@coredump.cx\>. Checkout the project [awesome-directed-fuzzing](https://github.com/strongcourage/awesome-directed-fuzzing) for related work on directed greybox/whitebox fuzzing.

# Integration into OSS-Fuzz
The easiest way to use AFLGo is as patch testing tool in OSS-Fuzz. Here is our integration:
* https://github.com/aflgo/oss-fuzz

# Environment Variables
* **AFLGO_INST_RATIO** -- The proportion of basic blocks instrumented with distance values (default: 100).
* **AFLGO_SELECTIVE** -- Add AFL-trampoline only to basic blocks with distance values? (default: off).
* **AFLGO_PROFILING_FILE** -- When CFG-tracing is enabled, the data will be stored here.

# How to instrument a Binary with AFLGo
1) Install <a href="https://llvm.org/docs/CMake.html" target="_blank">LLVM</a> **11.0.0** with <a href="http://llvm.org/docs/GoldPlugin.html" target="_blank">Gold</a>-plugin. You can also follow <a href="https://github.com/aflgo/oss-fuzz/blob/master/infra/base-images/base-clang/checkout_build_install_llvm.sh" target="_blank">these</a> instructions or run [AFLGo building script](./scripts/build/aflgo-build.sh).
2) Install other prerequisite
```bash
sudo apt-get update
sudo apt-get install python3
sudo apt-get install python3-dev
sudo apt-get install python3-pip
sudo apt-get install libboost-all-dev  # boost is not required if you use genDistance.sh in step 7
sudo pip3 install --upgrade pip
sudo pip3 install networkx
sudo pip3 install pydot
sudo pip3 install pydotplus
```
3) Compile AFLGo fuzzer, LLVM-instrumentation pass and the distance calculator
```bash
# Checkout source code
git clone https://github.com/aflgo/aflgo.git
export AFLGO=$PWD/aflgo

# Compile source code
pushd $AFLGO
make clean all 
cd llvm_mode
make clean all
cd ..
cd distance_calculator/
cmake -G Ninja ./
cmake --build ./
popd
```
4) Download subject (e.g., <a href="http://xmlsoft.org/" target="_blank">libxml2</a>) or just run [libxml2 fuzzing script](./scripts/fuzz/libxml2-ef709ce2.sh).
```bash
# Clone subject repository
git clone https://gitlab.gnome.org/GNOME/libxml2
export SUBJECT=$PWD/libxml2
```
5) Set targets (e.g., changed statements in commit <a href="https://git.gnome.org/browse/libxml2/commit/?id=ef709ce2" target="_blank">ef709ce2</a>). Writes BBtargets.txt.
```bash
# Setup directory containing all temporary files
mkdir temp
export TMP_DIR=$PWD/temp

# Download commit-analysis tool
wget https://raw.githubusercontent.com/jay/showlinenum/develop/showlinenum.awk
chmod +x showlinenum.awk
mv showlinenum.awk $TMP_DIR

# Generate BBtargets from commit ef709ce2
pushd $SUBJECT
  git checkout ef709ce2
  git diff -U0 HEAD^ HEAD > $TMP_DIR/commit.diff
popd
cat $TMP_DIR/commit.diff |  $TMP_DIR/showlinenum.awk show_header=0 path=1 | grep -e "\.[ch]:[0-9]*:+" -e "\.cpp:[0-9]*:+" -e "\.cc:[0-9]*:+" | cut -d+ -f1 | rev | cut -c2- | rev > $TMP_DIR/BBtargets.txt

# Print extracted targets. 
echo "Targets:"
cat $TMP_DIR/BBtargets.txt
```
6) **Note**: If there are no targets, there is nothing to instrument!
7) Generate CG and intra-procedural CFGs from subject (i.e., libxml2).
```bash
# Set aflgo-instrumenter
export CC=$AFLGO/afl-clang-fast
export CXX=$AFLGO/afl-clang-fast++

# Set aflgo-instrumentation flags
export COPY_CFLAGS=$CFLAGS
export COPY_CXXFLAGS=$CXXFLAGS
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
export CFLAGS="$CFLAGS $ADDITIONAL"
export CXXFLAGS="$CXXFLAGS $ADDITIONAL"

# Build libxml2 (in order to generate CG and CFGs).
# Meanwhile go have a coffee ☕️
export LDFLAGS=-lpthread
pushd $SUBJECT
  ./autogen.sh
  ./configure --disable-shared
  make clean
  make xmllint
popd
# * If the linker (CCLD) complains that you should run ranlib, make
#   sure that libLTO.so and LLVMgold.so (from building LLVM with Gold)
#   can be found in /usr/lib/bfd-plugins
# * If the compiler crashes, there is some problem with LLVM not 
#   supporting our instrumentation (afl-llvm-pass.so.cc:540-577).
#   LLVM has changed the instrumentation-API very often :(
#   -> Check LLVM-version, fix problem, and prepare pull request.
# * You can speed up the compilation with a parallel build. However,
#   this may impact which BBs are identified as targets. 
#   See https://github.com/aflgo/aflgo/issues/41.


# Test whether CG/CFG extraction was successful
$SUBJECT/xmllint --valid --recover $SUBJECT/test/dtd3
ls $TMP_DIR/dot-files
echo "Function targets"
cat $TMP_DIR/Ftargets.txt

# Clean up
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt

# Generate distance ☕️
# $AFLGO/scripts/genDistance.sh is the original, but significantly slower, version
$AFLGO/scripts/gen_distance_fast.py $SUBJECT $TMP_DIR xmllint

# Check distance file
echo "Distance values:"
head -n5 $TMP_DIR/distance.cfg.txt
echo "..."
tail -n5 $TMP_DIR/distance.cfg.txt
```
8) Note: If `distance.cfg.txt` is empty, there was some problem computing the CG-level and BB-level target distance. See `$TMP_DIR/step*`.
9) Instrument subject (i.e., libxml2)
```bash
export CFLAGS="$COPY_CFLAGS -distance=$TMP_DIR/distance.cfg.txt"
export CXXFLAGS="$COPY_CXXFLAGS -distance=$TMP_DIR/distance.cfg.txt"

# Clean and build subject with distance instrumentation ☕️
pushd $SUBJECT
  make clean
  ./configure --disable-shared
  make xmllint
popd
```

If your compilation crashes in this step, have a look at Issue [#4](https://github.com/aflgo/aflgo/issues/4#issuecomment-333947041).

# How to fuzz the instrumented binary
* We set the exponential annealing-based power schedule (-z exp).
* We set the time-to-exploitation to 45min (-c 45m), assuming the fuzzer is run for about an hour.
```bash
# Construct seed corpus
mkdir in
cp $SUBJECT/test/dtd* in
cp $SUBJECT/test/dtds/* in

$AFLGO/afl-fuzz -S ef709ce2 -z exp -c 45m -i in -o out $SUBJECT/xmllint --valid --recover @@
```
* **Tipp**: Concurrently fuzz the most recent version as master with classical AFL :)
```bash
$AFL/afl-fuzz -M master -i in -o out $MASTER/xmllint --valid --recover @@
```
* Run more [fuzzing scripts](./scripts/fuzz) of various real programs like Binutils, jasper, lrzip, libming and DARPA CGC. 
