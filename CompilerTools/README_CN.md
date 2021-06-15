# GCC测试工具

本项目基于编译器自身覆盖率信息对于测试程序进行选择，提供预测测试程序是否执行超时的功能，以及揭错代码缺陷度量功能。主要针对[GCC-4.4.0](https://gcc.gnu.org/)进行测试。

-----

## 环境
**1.从GitHub克隆GCC仓库，切换版本为4.4.0，或者直接[下载](https://github.com/gcc-mirror/gcc/archive/refs/tags/releases/gcc-4.4.0.tar.gz)。**
```
git clone https://github.com/gcc-mirror/gcc.git
cd gcc
git checkout -f b7fc996
```

**2.在编译GCC时，添加`--enable-coverage`选项，在GCC编译时进行动态插桩。**

**3.使用如下命令安装python3所需依赖：**

```
pip install -r requirement.txt
```

**4.编译安装[Csmith-2.3.0](https://embed.cs.utah.edu/csmith/csmith-2.3.0.tar.gz)**
```
cd [csmith-root]
./configure
make
```

## 用法

**1. `vector.py`用于预测测试程序是否超时，使用如下命令查看详细参数列表**

```
python3 vector.py -h
```

**2. `bug_hunter.py`用于度量揭错代码触发的缺陷，使用如下命令查看详细参数列表**

```
python3 bug_hunter.py -h
```


**注意! ! !** 编译GCC需要一定的编译经验。

