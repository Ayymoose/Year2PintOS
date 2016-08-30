#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include <hash.h>
#include "threads/synch.h"

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* Thread nice values */
#define NICE_DEFAULT 0                  /* Default nice value */
#define NICE_MIN -20                    /* Lowest nice value */
#define NICE_MAX 20                     /* Highest nice value */

#define ERROR_STATUS -1                 /* Thread error status */


/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Base priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Used by priority scheduler */
    struct list donations;              /* List of donations made to thread.
                                           This list is ordered in terms of
                                           priority_donated (descending)*/
    struct lock *wait_lock;             /* If the thread is waiting on a lock
                                          it will be stored here */
    struct semaphore *wait_sema;        /* If the thread is waiting on a
                                          semaphore it will be stored here */

    /* Used by advanced scheduler */
    int nice_value;                     /* The nice integer value used to
                                           determine how much of the cpu the
                                           thread is willing to share */
    int32_t recent_cpu;                 /* Used to determine how much of the
                                           cpu the thread has used recently */


    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    bool is_user_process;               /* True if thread is user process  */
    struct list_elem process_elem;      /* List elem for process list      */

    int exit_status;                    /* Exit status of process exiting  */
    struct list child_processes;        /* List of process_state structs   */
    struct list open_files;             /* List of open files used by a
                                           process */

    struct file *exe_file;                /* process executable file */

    uint32_t *pagedir;                  /* Page directory. */

    bool exited;                        /* If process thread has exited */
    bool waited;                        /* If parent thread has called wait */
    struct thread *parent;              /* The parent of the thread */

    struct semaphore sema_wait;         /* Semaphore for process_wait. */
    struct semaphore sema_exit;         /* Semaphore for process_exit. */
#endif

#ifdef VM
    struct hash supp_page_table;
    struct lock supp_page_table_lock;   /* Lock to ensure syncronous access */
    struct list mmap_files;             /* List of memory mapped files */
#endif
    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

/* A single donation made by a thread donor to another thread */
struct donation {
  struct thread *donor;                /* Thread that has donated priority */
  int priority_donated;                /* Priority donated by the donor thread*/
  struct lock *donor_lock;             /* The lock the donor is waiting to
                                          acqure */
  struct list_elem elem;               /* List element */

};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

/* Priority scheduling proto types */
int total_priority(struct thread *t);
void yield_for_highest(void);
bool thread_priority_less_func(const struct list_elem *a,
                               const struct list_elem *b,
                               void *aux UNUSED);

/* Advanced Scheduler proto types */
int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

/* Donations scheduler proto types */
void donate(struct donation *d, struct lock *lock);
void remove_donations(struct lock *lock);

struct thread * thread_by_tid(tid_t tid);

#endif /* threads/thread.h */
