# CrashVerify
This tool is used to get the location line of the crash

# Environment
Python2.7
Ubuntu 16.04 64bit

# Description
## Class Reproduce

* target_bin: the absolute path of the program that needs to be run, including the command to run the program.
* input_dir: the folder path is used to hold all crashes. 

* output_dir: the folder path is used to hold temporary files, eg: run.log.

* input_type: a flag that identifies the type of program input. stdin: input from standard input stream; symfile: input from local file.



# Usage
```
python run_verify.py \
-t "/root/aflgo-fuzz/build/out/207/noinstrument/jasper -f @@ -t mif -F /tmp/out -T jpg" \
-d /root/aflgo-fuzz/build/out/207/  \
-i /root/aflgo-fuzz/build/outBak/207/fuzzer_dir/crashes \
-b symfile
```

`-t` : command and parameters used to run the program<br>
`-d` : the directory path where the outputs save<br>
`-i` : the path to save all crashes<br>
`-b` : a flag that identifies the type of program input(stdin or symfile)<br>