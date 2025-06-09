这里表演直接用二进制可执行文件来改写write系统调用输出的内容。

为了修改简单，会在二进制可执行文件里使用shell脚本来生成改写后的内容，这个shell脚本里就可以自由发挥了，你可以用三剑客搞事情。

# 编译方法

```bash
make
```

# 使用方法

打开两个终端，假设是A和B

A终端：

```bash
cat
```

B终端：

```bash
ps -ef | grep -w cat    # 搜索A终端的cat的进程PID

# 假如输出是：
# root      9473  9428  0 01:48 pts/1    00:00:00 cat
# root      9491  9126  0 01:49 pts/0    00:00:00 grep --color=auto -w cat
# 则这里cat的PID是9473

./modify_write 9473 ./test_script.sh    # 这里的9473根据你实际上想改写write输出的进程PID来，./test_script.sh可以用你自己的脚本
```

回到A终端，这个时候，你会发现你在A终端里cat的输出全被改写了。
