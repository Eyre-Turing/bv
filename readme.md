bv - Brain in a Vat

# 功能

干预所有系统调用，让操作系统看到的只是你想让它看到的。

# 示例

示例里有一个程序，是可以让被ptrace到的进程的所有read系统调用读取到的大写字母都转换为小写的，可以这样执行得到效果：

```bash
make all

sudo ./bvd daemon
sudo ./bvctl $(pwd)/module/example/example.so
cat &
sudo ./bvctl $!
fg %1
```

之后在这个cat程序里，你将会发现，你输入的所有大写字母都会变成小写字母输出，这是因为bvd加载了example.so模块，而example.so模块的作用就是把ptrace到的进程read到的大写字母全部转换为小写字母。

想要结束bvd，可以执行：

```bash
sudo ./bvctl stop
```
