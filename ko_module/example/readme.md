使用内核模块不失为一种暴力篡改系统调用的方法，这里将表演如何篡改write系统调用，让系统调用在每次写的时候都先写一个`[write] `前缀。

当然，因为内核模块可以改全局，所以这里判断了是cat且是往标准输出写内容才做这个篡改，要不然影响太大（为之前就是搞全局，然后电脑就发癫了）。

# 编译方法

```bash
make
```

# 使用方法

```bash
sudo insmod ./hook_write.ko
echo hello | cat
```

# 解除方法

```bash
sudo rmmod hook_write
```
