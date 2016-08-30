#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "userprog/syscall.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line)
{
  char *file_name;
  char *fn_copy;
  char *save_ptr;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, cmd_line, PGSIZE);

  /* Copy of cmd_line used to ensure the original cmd_line isnt
     altered by strtok_r. Also avoids race between process trees */
  int cmd_len = strlen(cmd_line)+1;
  char cmd_copy[strlen(cmd_line)+1];
  strlcpy(cmd_copy, cmd_line, cmd_len);

  /* Extract file name from first token of command line argument */
  file_name = strtok_r(cmd_copy, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);

  if (tid == TID_ERROR)
    palloc_free_page (fn_copy);

  /* Wait for child thread to finish initialising itself */
  struct thread *new_process = thread_by_tid(tid);
  sema_down(&new_process->sema_wait);

  /* If the child thread had an error initialising itself then return error
     status (-1) */
  if (new_process->exit_status == ERROR_STATUS)
    return ERROR_STATUS;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *arguments_)
{
  char *arguments = (char *)arguments_;
  char *file_name = strtok_r (arguments, " ", &arguments);
  struct intr_frame if_;
  struct thread *curr = thread_current();

  bool success;
  curr->is_user_process = true;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  if (curr->parent != NULL)
    sema_up(&curr->sema_wait);

  /* If load failed, quit. */
  if (!success) {
    palloc_free_page (arguments_);
    exit(ERROR_STATUS);
  }

  /* Pushing of arguments onto the stack */
  push_arguments(file_name, arguments, &if_.esp);

  palloc_free_page (arguments_);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Returns the number of tokens in str */
int
num_tokens(const char *str) {
  int count = 0;
  char *token, *save_ptr;

  int len = strlen(str)+1; /* Number of chars in str and +1 for null terminal */
  char strcopy[len]; /* A copy of str */
  strlcpy(strcopy, str, len);

  for (token = strtok_r (strcopy, " ", &save_ptr); token != NULL;
       token = strtok_r (NULL, " ", &save_ptr)) {
    count++;
  }

  return count;

};

/* Pushes all arguments in argvs on the stack using the stack pointer esp.
   Pushes extra bytes if needed to ensure the esp is a multiple of 4 */
int
push_arguments(char *file_name, char *arguments, void **esp) {
  char *arg; /* current argument */
  char *arg_save_ptr; /* strtok_r save pointer */
  int i = 0; /* array index */

  int argc = num_tokens(arguments) + 1; /* +1 for file name */;
  char **argvAddr[argc]; /* Array of argv locations on the stack */

  /* Push file name onto the stack */
  push_arg(file_name, esp);
  /* Saving stack pointer for filename in argvAddr */
  argvAddr[i++] = (char **)*esp;

  /* Push all arguments onto stack */
  for (arg = strtok_r (arguments, " ", &arg_save_ptr); arg != NULL;
       arg = strtok_r (NULL, " ", &arg_save_ptr)) {

    /* If number of arguments exceed maximum arguments stack size then return 0
       to signal an error */
    if (PHYS_BASE - *esp > MAX_ARGS_SIZE)
      return 0;

    ASSERT(i < argc);
    push_arg(arg, esp);

    /* Saving stack pointer to argument in argvAddr */
    argvAddr[i++] = (char **)*esp;
  }

  /* The number of bytes pushed onto the stack to ensure the esp is a multiple
  of 4 */
  int num_word_align = WORD_SIZE - ((uint32_t)*esp % WORD_SIZE);

  for (i = 0; i < num_word_align; i++)
    push_byte(esp);

  /* Null pointer terminal */
  push_arg_ptr(0, esp);

  /* Push each argument stack pointer location (in reverse order) */
  for (i = argc - 1; i >= 0; i--)
    push_arg_ptr(argvAddr[i], esp);


  /* argv: pointer to first address of argv */
  char **arg_base_ptr = (char **)*esp;

  /* Push argv addr to stack */
  *esp = (uint32_t *)*esp - 1;
  *(char ***)*esp = arg_base_ptr;

  /* Push argc onto stack */
  *esp = (void *)((int *)*esp - 1);
  *(int *)*esp = argc;

  /* Push fake return address */
  *esp = (uint32_t *)*esp - 1;
  *(void **)*esp = NULL;

  /* Successful stack set up */
  return 1;
}

/* Using the stack pointer esp, the arg is pushed onto the stack */
void
push_arg(char *arg, void **esp)
{
  /* Decrement the stack pointer by the length of the string */
  int arglen = strlen(arg) + 1; /* length of string plus /0 */
  *esp = (void *)((char *)*esp - arglen);

  /* Push arg onto the stack */
  strlcpy((char *)*esp, arg, arglen);
}

/* Pushes an empty byte of 0's onto the stack */
void
push_byte(void **esp) {
  /* Decrement the stack pointer by 1 byte */
  *esp = (void *)((uint8_t *)*esp - 1);

  /* Push arg on to the stack */
  *(uint8_t*)*esp = 0;
}

/* Pushes an argument pointer to the stack */
void
push_arg_ptr(char **arg_ptr, void **esp) {
  /* Decrement the stack pointer by the size of a word */
  *esp = (uint32_t *)*esp - 1;

  /* Push arg pointer onto the stack */
  *(char ***)*esp = arg_ptr;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.

   If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid)
{
  int ret;
  struct thread *t = thread_by_tid (child_tid);
  /* If there is no child thread OR
     not a child of the calling process OR
     if process_wait() has already been called on this thread */
  if (t == NULL || t->parent != thread_current () || t->waited) {
    return ERROR_STATUS;
  }

  t->waited = true;

  /* If the child has exited */
  if (t->exited == true) {
    return t->exit_status;
  }

  sema_down (&t->sema_wait);
  ret = t->exit_status;
  sema_up (&t->sema_exit);
  return ret;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  printf ("%s: exit(%d)\n", cur->name, cur->exit_status);

  /* Unblock all process waiting on current thread */
  while (!list_empty (&cur->sema_wait.waiters))
    sema_up (&cur->sema_wait);

  cur->exited = true;
  if (cur->parent != NULL)
    sema_down (&cur->sema_exit);

  #ifdef VM
  destroy_supp_page_table(&cur->supp_page_table);
  #endif

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Set threads exe file field and deny writes to it during the duration of the
     process */
  t->exe_file = file;
  if (file != NULL)
    file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset.*/
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      off_t block_id = -1;

      /* If we have a read-only segment obtain its corresponding block sector
      to be used later on in sharing read-only frames. */
      lock_acquire(&file_system_lock);
      if (writable == false)
        block_id = inode_get_block_number (file_get_inode (file), ofs);
      lock_release(&file_system_lock);

      struct page *new_page = NULL;
      new_page = create_file_page(upage, file, ofs, page_read_bytes,
        writable, block_id);

      if (new_page == NULL)
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
 void *stk_vaddr = (uint8_t *) PHYS_BASE - PGSIZE;

 if (create_zero_page(stk_vaddr) == NULL)
   return false;

 *esp = PHYS_BASE;
 return load_page(stk_vaddr);
}


/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with frame_alloc().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
