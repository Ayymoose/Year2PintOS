#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "vm/mmap.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "exception.h"


static void syscall_handler (struct intr_frame *);

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

typedef int pid_t;

static void halt (void);
static pid_t exec (const char * cmd_line);
static int wait (pid_t pid);
static bool create (const char * file, unsigned initial_size);
static bool remove (const char * file);
static int open (const char * file);
static int filesize (int fd);
static int read (int fd, void * buffer, unsigned size);
static int write (int fd, const void * buffer, unsigned size);
static void seek (int fd, unsigned position);
static unsigned tell (int fd);
static void close (int fd);
static void close_file(struct file_state *f_state);
static uint32_t add_file_state(struct file *f);
static void init_file_state(struct file_state *f_state, struct file *f);
static struct file *find_file_by_fd (int fd);
static struct thread *get_child (struct thread *parent, pid_t pid);

static void move_stack(void **esp, int num_bytes_moved);
static uint32_t generate_fd (void);

static void *stack_esp;
struct lock read_write_lock;

/* Moves the esp by num_bytes bytes. If this variable is negative then the esp
   is decreased */
static void move_stack(void **esp, int num_bytes) {
  *esp = *esp + num_bytes;
}

void
syscall_init (void)
{
  lock_init(&file_system_lock);
  lock_init(&read_write_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
validate_sp_and_dir(void *saved_sp, uint32_t *pd) {
if (saved_sp == NULL)
  exit(ERROR_STATUS);

if (!( is_user_vaddr ((uint32_t *) saved_sp + 0) &&
       is_user_vaddr ((uint32_t *) saved_sp + 1) &&
       is_user_vaddr ((uint32_t *) saved_sp + 2) &&
       is_user_vaddr ((uint32_t *) saved_sp + 3)))
  exit(ERROR_STATUS);

if (pagedir_get_page(pd, saved_sp) == NULL)
  exit(ERROR_STATUS);
}

static void
syscall_handler (struct intr_frame *f)
{

  uint32_t *pd = thread_current()->pagedir;
  void *saved_sp = f->esp;
  stack_esp = f->esp;

  validate_sp_and_dir(saved_sp, pd);

  int ret_value = 0; /* restored here */
  uint32_t system_call_number = *(uint32_t*)saved_sp;
  move_stack(&saved_sp, sizeof(uint32_t));

  switch (system_call_number) {
   case SYS_HALT:
      halt();

    break;
  case SYS_EXIT:
    {
      int status_arg = *(int*)saved_sp;

      exit(status_arg);
    }
    break;
  case SYS_EXEC:
    {
      const char *cmd_line = *(const char **)saved_sp;

      ret_value = exec(cmd_line);
    }
    break;
  case SYS_WAIT:
    {
      pid_t pid = *(pid_t*)saved_sp;

      ret_value = wait(pid);
    }
    break;
  case SYS_CREATE:
    {
      const char *file = *(const char **)saved_sp;
      move_stack(&saved_sp, sizeof(char*));
      unsigned initial_size = *(unsigned*)saved_sp;

      ret_value = (int)create(file, initial_size);
    }
    break;
  case SYS_REMOVE:
    {
      const char *file = *(const char **)saved_sp;

      ret_value = (int)remove(file);
    }
    break;
  case SYS_OPEN:
    {
      const char *file = *(const char **)saved_sp;

      ret_value = open(file);
    }
    break;
  case SYS_FILESIZE:
    {
      int file_size = *(int*)saved_sp;

      ret_value = filesize(file_size);
    }
    break;
  case SYS_READ:
    {
      int fd_arg = *(int*)saved_sp;
      move_stack(&saved_sp, sizeof(int));
      void *buffer_arg = *(void **)saved_sp;
      move_stack(&saved_sp, WORD_SIZE);
      unsigned size_arg = *(unsigned*)saved_sp;

      ret_value = read(fd_arg, buffer_arg, size_arg);
    }
    break;
  case SYS_WRITE:
    {
      int fd_arg = *(int*)saved_sp;
      move_stack(&saved_sp, sizeof(int));
      void *buffer_arg = *(void **)saved_sp;
      move_stack(&saved_sp, WORD_SIZE);
      unsigned size_arg = *(unsigned*)saved_sp;

      ret_value = write(fd_arg, buffer_arg, size_arg);
    }
    break;
  case SYS_SEEK:
    {
      int fd_arg = *(int*)saved_sp;
      move_stack(&saved_sp, sizeof(int));
      unsigned position = *(unsigned*)saved_sp;

      seek(fd_arg, position);
    }
    break;
  case SYS_TELL:
    {
      int fd = *(int*)saved_sp;

      ret_value = tell(fd);
    }
    break;
  case SYS_CLOSE:
    {
      int fd = *(int*)saved_sp;

      close(fd);
    }
    break;
  case SYS_MMAP:
    {
      int fd = *(int*)saved_sp;
      move_stack(&saved_sp, sizeof(int));
      void *vaddr = *(void **)saved_sp;
      ret_value = mmap(fd, vaddr);
    }
    break;
  case SYS_MUNMAP:
    {
      int map_id = *(int*)saved_sp;
      munmap(map_id);
    }
    break;
  }

  /* Push return value on to stack */
  f->eax = ret_value;
}

static void
halt (void)
{
  shutdown_power_off();
}

void
exit (int status)
{
  struct thread *cur_thread = thread_current();
  cur_thread->exit_status = status;
  closeAll();

  /* Now the lifespan of the executable process has ended, allow writes to
     its executable file then close the file */
  if (cur_thread->exe_file != NULL) {
    file_allow_write(cur_thread->exe_file);
    file_close(cur_thread->exe_file);
    cur_thread->exe_file = NULL;
  }

  struct list_elem *e;
  /* Unmap all memory mapped files of the thread */
  while (!list_empty(&cur_thread->mmap_files)) {
      e = list_begin(&cur_thread->mmap_files);

      int mmap_id = list_entry (e, struct mmap_entry, thread_elem)->map_id;
      munmap(mmap_id);
  }

  thread_exit();
}

static pid_t
exec (const char * cmd_line) {
  struct thread *parent = thread_current();
  tid_t process_id = process_execute(cmd_line);

  if (process_id != TID_ERROR)
  {
    struct thread *new_process = thread_by_tid(process_id);
    new_process->parent = parent;
    list_push_back(&parent->child_processes, &new_process->process_elem);
  }

  return process_id;
}

static int
wait (pid_t pid)
{
  /* If pid is alive, wait for termination, return status pid passed to exit
     if pid DID NOT call exit but terminated by kernel (exception), return -1 */
  struct thread *child = get_child(thread_current(), pid);
  if (child == NULL)
    return ERROR_STATUS;
  return process_wait(pid);
}

static bool
create (const char * file, unsigned initial_size){
  if (file == NULL || strlen(file) < 1)
    exit (ERROR_STATUS);

  if (strlen(file) > MAX_FILE_NAME_LENGTH) {
    return false;
  }

  lock_acquire(&file_system_lock);
  bool result = filesys_create(file, initial_size);
  lock_release(&file_system_lock);

  return result;
}

static bool
remove (const char * file){
  if (file == NULL)
    exit(ERROR_STATUS);

  /* Remove the file so that any file that tries to open the removed file
     will fail */
  lock_acquire(&file_system_lock);
  bool result = filesys_remove(file);
  lock_release(&file_system_lock);

  return result;
}

static int
open (const char * file){

  if (file == NULL)
    return ERROR_STATUS;

  lock_acquire(&file_system_lock);

  struct file *system_file = filesys_open(file);

  lock_release(&file_system_lock);

  if (system_file == NULL)
    return ERROR_STATUS;

  /* Generates a new file descriptor for the system_file and creates and adds
     A new file state for this fd and adds it to the current threads open_list*/
  int new_fd = add_file_state(system_file);

  /* If the there was an error creating the file state, close system_file */
  if (new_fd == ERROR_STATUS) {
    lock_acquire(&file_system_lock);
    file_close(system_file);
    lock_release(&file_system_lock);
  }

  return new_fd;
}


static int
filesize (int fd) {
  struct file *f = find_file_by_fd(fd);

  if (f == NULL)
    return ERROR_STATUS;

  lock_acquire(&file_system_lock);
  int file_size = file_length(f);
  lock_release(&file_system_lock);

  return file_size;

}

static int
read (int fd, void * buffer, unsigned size) {
  struct file *f = find_file_by_fd(fd);
  int size_read;

  // Check if invalid buffer pointer
  if(buffer + size - 1 >= PHYS_BASE ||
     put_user (buffer + size - 1, 0) == 0) {
    exit(ERROR_STATUS);
  }

  if (f == NULL) {
    exit(ERROR_STATUS);

  } else if (fd == 0) {  // Case reading from SDTIN
    unsigned i;
    for (i = 0; i < size; i++)
      *(uint8_t *)(buffer + i) = input_getc ();
    return size;

  } else {
    lock_acquire(&read_write_lock);
    size_t rem = size;

    size_read = 0;
    while (rem > 0)
    {
      /* start vaddr of current page */
      void *vaddr = pg_round_down(buffer);

      size_t offset = buffer - vaddr;
      struct page *p = find_page (vaddr);

      if (p == NULL && stack_out_of_bounds (stack_esp, buffer))
        p = grow_stack (vaddr);
      else if (p == NULL)
        exit (-1);

      size_t read_bytes = offset + rem > PGSIZE ?
                PGSIZE - offset : rem;

      ban_eviction(page_paddr(p));

      lock_acquire (&file_system_lock);
      size_read += file_read (f, buffer, read_bytes);
      lock_release (&file_system_lock);

      rem -= read_bytes;
      buffer += read_bytes;

      allow_eviction(page_paddr(p));
    }

    lock_release(&read_write_lock);
    return size_read;

  }

  return ERROR_STATUS;
}

/* Writes size bytes from buffer either to open file or console. */
static int
write (int fd, const void * buffer, unsigned size)
{
  struct file *f;
  int size_written;

  // Check if invalid buffer pointer
  if(buffer + size - 1 >= PHYS_BASE || get_user(buffer + size - 1) == -1)
    exit(ERROR_STATUS);

  if (fd == STDIN_FILENO) {  // Cannot write to system in
    return ERROR_STATUS;

  } else if (fd == STDOUT_FILENO) {  // Write to console
    putbuf(buffer, size);
    return size;

  } else {  // Attempt to write to file
    f = find_file_by_fd(fd);

    if (f == NULL) {
      return ERROR_STATUS;

    } else {
      lock_acquire(&read_write_lock);
      size_t rem = size;

      size_written = 0;
      while (rem > 0)
      {
        /* start vaddr of current page */
        void *vaddr = pg_round_down(buffer);

        size_t offset = buffer - vaddr;
        struct page *p = find_page (vaddr);

        if (p == NULL && stack_out_of_bounds (stack_esp, buffer))
          p = grow_stack (vaddr);
        else if (p == NULL)
          exit (-1);

        size_t write_bytes = offset + rem > PGSIZE ?
                  PGSIZE - offset : rem;

        ban_eviction(page_paddr(p));

        lock_acquire (&file_system_lock);
        size_written += file_write (f, buffer, write_bytes);
        lock_release (&file_system_lock);

        rem -= write_bytes;
        buffer += write_bytes;

        allow_eviction(page_paddr(p));
      }

      lock_release(&read_write_lock);
      return size_written;

    }

  }
}

static void
seek (int fd, unsigned position) {
  struct file *f = find_file_by_fd(fd);

  if(f == NULL) {
    exit(ERROR_STATUS);

  } else {
    lock_acquire(&file_system_lock);
    file_seek(f, position);
    lock_release(&file_system_lock);

  }
}

static unsigned
tell (int fd) {
  struct file *f = find_file_by_fd(fd);

  if (f == NULL)
    return ERROR_STATUS;

  lock_acquire(&file_system_lock);
  int file_position = file_tell(f);
  lock_release(&file_system_lock);

  return file_position;
}

static void
close (int fd)
{
  struct list *files = &thread_current()->open_files;

  struct list_elem *e;
  for (e = list_begin (files); e != list_end (files);
    e = list_next (e))
  {
    struct file_state *f_state = list_entry (e, struct file_state, elem);
    if (f_state->fd == fd) {
      close_file(f_state);
      return;
    }
  }

}

/* Removes the f_state from the list of open file states
   and closes the file within it */
static void
close_file(struct file_state *f_state) {
  lock_acquire(&file_system_lock);
  file_close(f_state->file);
  lock_release(&file_system_lock);

  list_remove(&f_state->elem);
  free(f_state);
}


/* Maps a file into the process's virtual address space. */
mapid_t
mmap (int fd, void *vaddr) {

  /* Find and reopen the file */
  lock_acquire (&file_system_lock);
  struct file *file = file_reopen (find_file_by_fd(fd));
  int file_size = file_length(file);
  lock_release (&file_system_lock);


  /* Error checking */

  /* Fail if file does not exit or if file_size is <= 0 bytes */
  if (file == NULL || file_size <= 0 )
    return -1;

  /* Fail if addr is zero, if not page-aligned, */
  if (vaddr == NULL || vaddr == 0x0 || pg_ofs (vaddr) != 0)
    return -1;

  /* Console I/O is not mappable*/
  if (fd == STDIN_FILENO || fd == STDOUT_FILENO)
    return -1;

  /* Fail if the range of pages mapped overlaps any existing mapped page */
  void *curr_vaddr = vaddr;
  while (curr_vaddr <= vaddr + file_size) {
    if (find_page(curr_vaddr) != NULL)
      return -1;
    curr_vaddr += PGSIZE;
  }


  /* Create mapping */
  curr_vaddr = vaddr;
  off_t offset = 0;

  while (file_size > 0) {
    uint32_t read_bytes;

    read_bytes = file_size >= PGSIZE ? PGSIZE : file_size;

    off_t block_id = inode_get_block_number (file_get_inode (file), offset);
    create_file_page(curr_vaddr, file, offset, read_bytes, true, block_id);

    offset += PGSIZE;
    curr_vaddr += PGSIZE;
    file_size -= read_bytes;
  }

  uint32_t map_id = generate_mapid();
  insert_mmap(map_id, fd, vaddr, curr_vaddr);

  return map_id;
}

/* Unmaps a file located at the start of a virtual address space. */
void
munmap (mapid_t map_id) {
  struct mmap_entry *me = find_mmap_entry(map_id);

  if (me == NULL) {
    exit (-1);
  }

  /* Start unmapping from the start virtual address of a maped entry */
  void *curr_vaddr = me->vaddr_begin;
  void *end_vaddr = me->vaddr_end;

  /* Free each mapped page */
  while (curr_vaddr < end_vaddr) {
    struct page *page = find_page(curr_vaddr);

    if (page == NULL)
      continue;

    page_destroy(page);
    curr_vaddr += PGSIZE;
  }
  delete_mmap_entry(map_id);
}

/* Closes all open files used by the current thread */
void
closeAll() {
  struct list *files = &thread_current()->open_files;

  while (!list_empty(files)) {
    struct list_elem *e = list_begin(files);
    struct file_state *f_state = list_entry (e, struct file_state, elem);
    close_file(f_state);
  }

}

/* Creates a new file state for file f with a new file descriptor. This file
   state is added to the current threads list of open files. The fd of the file
   state is return (-1 is returned if an error occured in creating the new
   file state) */
static uint32_t
add_file_state(struct file *f) {
  struct file_state *f_state
    = (struct file_state *) malloc(sizeof(struct file_state));

  if (f_state == NULL)
    return ERROR_STATUS;

  init_file_state(f_state, f);
  list_push_back (&thread_current ()->open_files, &f_state->elem);
  return f_state->fd;
}

/* Returns a new file state with the file f and a newly generated fd */
static void
init_file_state(struct file_state *f_state, struct file *f) {
  if (f_state == NULL)
    return;

  f_state->file = f;

  f_state->fd = generate_fd();
}

/* Finds and returns a file according to its fd, returns NULL otherwise */
static struct file *
find_file_by_fd (int fd)
{
  struct list *files = &thread_current()->open_files;

  struct list_elem *e;
  for (e = list_begin (files); e != list_end (files);
    e = list_next (e))
  {
    struct file_state *file_state = list_entry (e, struct file_state, elem);

    if (file_state->fd == fd)
    {
      return file_state->file;
    }
  }

  return NULL;
}

/* Returns child process of process PARENT user process from PID,
NULL if pid is not a child */
static struct thread*
get_child(struct thread *parent, pid_t pid) {
  struct list *children = &parent->child_processes;
  struct list_elem *child;
  for (child = list_begin(children); child != list_end(children);
     child = list_next(child))
   {
    struct thread *cp = list_entry(child, struct thread, process_elem);
    if (cp->tid == pid) {
      return cp;
    }
  }
  return NULL;
}

/* Returns a new unused file id */
static uint32_t
generate_fd (void)
{
  static uint32_t new_fd = 2;
  return new_fd++;
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int
get_user (const uint8_t *uaddr)
{
int result;
asm ("movl $1f, %0; movzbl %1, %0; 1:"
: "=&a" (result) : "m" (*uaddr));
return result;
}
/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
int error_code;
asm ("movl $1f, %0; movb %b2, %1; 1:"
: "=&a" (error_code), "=m" (*udst) : "q" (byte));
return error_code != ERROR_STATUS;
}
