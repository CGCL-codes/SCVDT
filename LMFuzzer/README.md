# LMFuzzer
LMFuzzer is a fuzzing system that uses probabilistic models to guide seed generation, which can test Java open-source software.
## Environment
You will need Java 8+ and Apache Maven 3.5+.
## Fuzzing a Compiler
Example:
https://github.com/rohanpadhye/jqf/wiki/Fuzzing-a-Compiler

you need to donwload cuda libtorch https://download.pytorch.org/libtorch/cu102/libtorch-shared-with-deps-1.8.1%2Bcu102.zip to /SCVDT/LMFuzzer/jqf-new/fuzz/LSTM/libtorch  as a library



#### Usage（UseLMFzzer）
```
$ cd SCVDT
$ cd LMFuzzer/jqf-new/
$ mvn package
$ ./bin/jqf-lm -c .:$(./scripts/examples_classpath.sh)   edu.berkeley.cs.jqf.examples.closure.CompilerTest testWithInputStream edu.berkeley.cs.jqf.examples.js.JavaScriptLSTMGenerator2 /path/to/jsSeed /path/to/jsCrop
```


##### Status screen

```
LM Fuzzing
--------------------

Test name:            edu.berkeley.cs.jqf.examples.closure.CompilerTest#testWithInputStream
Results directory:    /home/user/wxj/SCVDT/LMFuzzer/jqf-new/fuzz-results
Elapsed time:         3m 37s (no time limit)
Number of executions: 1,330
Valid inputs:         1,248 (79.27%)
Unique failures:      0
Execution speed:      22/sec now | 6/sec overall
Total coverage:       10,551 branches (16.10% of map)
Valid coverage:       10,500 branches (16.02% of map)
Unique valid inputs:  36 (2.71%)
Unique valid paths:   1,178 
''  non-zero paths:   1,099 
```
