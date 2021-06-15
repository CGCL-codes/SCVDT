# Introduction
The vulnerable code database (VulnDB) is a database for vulnerability patch files and their corresponding vulnerable source code and non-vulnerable source code. The database contains data from open-source projects `Asterisk`, `Chrome`, `FFmpeg`, `Firefox`, `ImagaMagick`, `LibPNG`, `LibTIFF`, `Linux Kernel`, `OpenSSL`, `OpenStack`, `PHP-SRC`, `Pidgin`, `QEMU`, `VLC Player`, `Wireshark`, `Xen`, `Binutils`, `JasPer` and `Libming`.

# Diffs
`TypeDiffs.zip` is a collection of diffs obtained by crawling and flitering commits from GitHub. There are several types of diffs, and different types represent the correlation between diffs and vulnerabilities. The diff name contains the CVE number, CWE type, patch file name and patch type.


| TYPE                 | DESCRIPTION                                                            |
|----------------------|-------------------------------------------------------------------------|
| 1.1             | There is a patch to the code fragment of the vulnerability `function` in diff   |
| 1.2             | There is a patch to the code fragment of the vulnerability `file` in diff  |
| 2.1             | There is a patch to the code fragment of the vulnerability `file` in diff, but there is no patch to the vulnerability function  |
| 3.1             | The diff is a fix for the vulnerability, because the page from which diff comes is marked with `CVE` |
| 4.0             | The correlation between the diff and the vulnerability cannot be determined |


# File-level vulnerability samples
`FileSamples.zip` is a collection of vulnerable file-level sample files and non-vulnerable file-level sample files. A file that ends with `.OLD` represents the vulnerable file-level sample file. A file that ends with `.NEW` represents the non-vulnerable file-level sample file.

# Function-level vulnerability samples
`FuncSamples.zip` is a collection of vulnerable function-level sample files and non-vulnerable function-level sample files. A file that ends with `.OLD` represents the vulnerable function-level sample file. A file that ends with `.NEW` represents the non-vulnerable function-level sample file.

