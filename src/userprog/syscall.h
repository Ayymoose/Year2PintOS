#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/thread.h"

#define MAX_FILE_NAME_LENGTH 14
typedef int mapid_t;

struct file_state
  {
    int fd;           /* file descriptor */
    struct file *file;
    struct list_elem elem;
  };

/* At most one process can access filesystem */
struct lock file_system_lock;

void syscall_init (void);
void closeAll(void);
void exit (int status);
mapid_t mmap(int fd, void *addr);
void munmap (mapid_t map_id);

#endif /* userprog/syscall.h */
