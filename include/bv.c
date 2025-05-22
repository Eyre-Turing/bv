#include <bv.h>
#include <stdlib.h>

int *bv_syscall_list = NULL;
int bv_syscall_list_len = 0;

void _init_var()
{
	bv_syscall_list = (int *) calloc(BV_SYSCALL_LIST_SIZE, sizeof(int));
	bv_syscall_list_len = 0;
}

void __attribute__((destructor)) _destroy_var()
{
	free(bv_syscall_list);
}
