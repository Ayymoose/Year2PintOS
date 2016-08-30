#ifndef USERPROG_EXCEPTION_H
#define USERPROG_EXCEPTION_H

#include <stdio.h>

/* Page fault error code bits that describe the cause of the exception.  */
#define PF_P 0x1    /* 0: not-present page. 1: access rights violation. */
#define PF_W 0x2    /* 0: read, 1: write. */
#define PF_U 0x4    /* 0: kernel, 1: user process. */

#define STACK_OVERFLOW_BOUND 32
#define MAX_STACK_SIZE 8388608

void exception_init (void);
void exception_print_stats (void);
bool stack_out_of_bounds (void *esp, void *vaddr);
struct page *grow_stack (void *vaddr);

#endif /* userprog/exception.h */
