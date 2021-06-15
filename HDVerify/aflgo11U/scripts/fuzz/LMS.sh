git clone https://github.com/trailofbits/cb-multios LMS
cd LMS; mv challenges all-challenges; mkdir -p challenges/LMS; cp -r all-challenges/LMS challenges
mkdir obj-aflgo; mkdir obj-aflgo/temp
export SUBJECT=$PWD; export TMP_DIR=$PWD/obj-aflgo/temp
export CC=$AFLGO/afl-clang-fast; export CXX=$AFLGO/afl-clang-fast++
export LDFLAGS=-lpthread
export ADDITIONAL="-targets=$TMP_DIR/BBtargets.txt -outdir=$TMP_DIR -flto -fuse-ld=gold -Wl,-plugin-opt=save-temps"
echo $'service.c:227\nservice.c:183\nservice.c:91\nlibc.c:503\nlibc.c:385' > $TMP_DIR/BBtargets.txt # empty distance.cfg.txt ?
LINK=STATIC CFLAGS="$ADDITIONAL" CXXFLAGS="$ADDITIONAL" ./build.sh
cat $TMP_DIR/BBnames.txt | rev | cut -d: -f2- | rev | sort | uniq > $TMP_DIR/BBnames2.txt && mv $TMP_DIR/BBnames2.txt $TMP_DIR/BBnames.txt
cat $TMP_DIR/BBcalls.txt | sort | uniq > $TMP_DIR/BBcalls2.txt && mv $TMP_DIR/BBcalls2.txt $TMP_DIR/BBcalls.txt
cd build/challenges/LMS; $AFLGO/scripts/genDistance.sh $SUBJECT $TMP_DIR LMS
cd -; rm -rf build; LINK=STATIC CFLAGS="-g -distance=$TMP_DIR/distance.cfg.txt" CXXFLAGS="-g -distance=$TMP_DIR/distance.cfg.txt" ./build.sh
cd -; mkdir in; echo "" > in/in
$AFLGO/afl-fuzz -m none -z exp -c 45m -i in -o out ./LMS