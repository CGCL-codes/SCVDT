# GCC-Testing-Tools
**English** | [中文](README_CN.md)

This project selects the test program based on the compiler's own coverage information, and provides the function of predicting whether the test program will run timeout, as well as the function of measuring bug-revealing-program's bug. Mainly for [gcc-4.4.0](https://gcc.gnu.org/).

-----

## Environment
**1.Clone GCC repository from GitHub, switch the version to 4.4.0, or [download](https://github.com/gcc-mirror/gcc/archive/refs/tags/releases/gcc-4.4.0.tar.gz) it directly.**
```
git clone https://github.com/gcc-mirror/gcc.git
cd gcc
git checkout -f b7fc996
```

**2.Add ` --enable-coverage ` option when compiling GCC.**

**3.Just run the following command to install the dependencies required for python3：**

```
pip install -r requirement.txt
```

**4.Compiling and installing [Csmith-2.3.0](https://embed.cs.utah.edu/csmith/csmith-2.3.0.tar.gz)**
```
cd [csmith-root]
./configure
make
```

## Usage

**1. `Vector.py` is used to predict whether the test program will time out. Use the following command to view the detailed parameter list:**

```
python3 vector.py -h
```

**2. ` bug_hunter.py ` is used to measure the bugs triggered by the bug-revealing program. Use the following command to view the detailed parameter list:**

```
python3 bug_hunter.py -h
```


**Notice! ! !** You'd better have some experience on compiling GCC.

