// 这个内核模块里将表演如何把所有cat往标准输出写的所有行都加上[write] 前缀

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/fs.h>

// 保存原始系统调用函数指针
static asmlinkage long (*original_write)(unsigned int fd, const char __user *buf, size_t count);

// 自定义的write系统调用函数
static asmlinkage long hacked_write(unsigned int fd, const char __user *buf, size_t count) {
	struct pid *pid_struct = find_get_pid(current->pid);
	struct task_struct *task = get_pid_task(pid_struct, PIDTYPE_PID);
	char path[PATH_MAX];
	char *path_p;
	mm_segment_t old_fs;

	if (task) {
		if (task->mm && task->mm->exe_file) {
			path_p = d_path(&task->mm->exe_file->f_path, path, sizeof(path));
		}
		put_task_struct(task);
	}
	put_pid(pid_struct);

	if (strcmp(kbasename(path_p), "cat") == 0 && fd == 1) {
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		original_write(fd, "[write] ", 8);	// 写入前缀，效果是cat每行输出到标准输出的内容都加上[write] 前缀
		set_fs(old_fs);
		return original_write(fd, buf, count);
	}

	return original_write(fd, buf, count);
}

// 模块初始化函数
static int __init hook_init(void) {
	// 获取系统调用表地址（需root权限）
	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (!sys_call_table) {
		printk(KERN_ERR "Failed to find sys_call_table\n");
		return -ENXIO;
	}

	// 保存原始的write系统调用
	original_write = (void *)sys_call_table[__NR_write];

	// 替换为自定义函数（关闭写保护）
	write_cr0(read_cr0() & (~0x10000));  // 禁用CR0的写保护位
	sys_call_table[__NR_write] = (unsigned long)hacked_write;
	write_cr0(read_cr0() | 0x10000);     // 恢复写保护

	printk(KERN_INFO "Hooked write syscall\n");
	return 0;
}

// 模块退出函数
static void __exit hook_exit(void) {
	unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (sys_call_table) {
		write_cr0(read_cr0() & (~0x10000));
		sys_call_table[__NR_write] = (unsigned long)original_write;
		write_cr0(read_cr0() | 0x10000);
		printk(KERN_INFO "Restored original write syscall\n");
	}
}

module_init(hook_init);
module_exit(hook_exit);
MODULE_LICENSE("GPL");
