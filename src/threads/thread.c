#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/fixed-point.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "threads/malloc.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif
#ifdef VM
#include "vm/page.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Lock for atomising changing a threads priority */
static struct lock set_priority_lock;

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

/* Load average for the system in 17.14 fixed-point format */
static int32_t load_avg;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority,
                         int nice_value);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Priority scheduler proto types */
static int get_highest_priority(void);
static bool is_highest_priority(void);

/* Donations scheduler proto types */
static bool has_donations(struct thread *t);
static bool donation_less_func(const struct list_elem *a,
                       const struct list_elem *b, void *aux UNUSED);
static void init_donation(struct donation *d, struct lock *donor_lock,
   struct thread *donor);
static void add_donation(struct donation *new_donation);
static void update_donation(struct lock *lock, struct thread *donor);
static void update_wait_list(struct thread *t);
static struct donation *get_donor_donation(struct lock *lock,
   struct thread *donor);

/* Advanced scheduler proto types */
static void recalculate_recent_cpu_foreach(struct thread *t,
   void *unused UNUSED);
static void thread_recalculate_priority(struct thread *t);
static void thread_recalculate_recent_cpu(struct thread *t);
static void thread_recalculate_load_avg(void);
static void recalculate_BSD_scheduler_vars(void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void)
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init(&set_priority_lock);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT, NICE_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  /* If BSD scheduler is being used then recalculate its variables */
  if (thread_mlfqs) {
    recalculate_BSD_scheduler_vars();
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE) {
    intr_yield_on_return();
  }
}

/* Recalculates the variables of the BSD scheduler */
static void
recalculate_BSD_scheduler_vars(void)
{
  ASSERT(thread_mlfqs);

  struct thread *t = thread_current ();

  /* Increment the current thread's recent cpu value. */
  if (thread_current () != idle_thread) {
    t->recent_cpu = add_fixed_to_int (t->recent_cpu, 1);
  }

  /* Update recent cpu and load avg every second. */
  if (timer_ticks () % TIMER_FREQ == 0) {
    thread_recalculate_load_avg ();
    thread_foreach (&recalculate_recent_cpu_foreach, NULL);
  }

  /* Recalculates priority for the running thread every 4 ticks. */
  if (timer_ticks () % TIME_SLICE == 0) {
    thread_recalculate_priority(t);
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
             thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  int nice_value;

  if (thread_mlfqs) {
    nice_value = thread_get_nice();
  } else {
    nice_value = NICE_DEFAULT;
  }

  init_thread (t, name, priority, nice_value);


  if (thread_mlfqs) {
    // Recalcuates priority for new thread
    thread_recalculate_priority(t);
  }

  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack'
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  #ifdef USERPROG

  /* Initialise child thread's fields */
  t->parent = thread_current();
  t->exit_status = 0;
  t->exited = false;
  t->waited = false;

  #endif

  #ifdef VM
  init_supp_page_table(&t->supp_page_table, &t->supp_page_table_lock);
  #endif

  /* Add to run queue.*/
  thread_unblock (t);
  /* Yield for the newly unblocked thread if it has the higher priority */
  yield_for_highest();

  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t)
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);

  // Insert unblocked thread in terms of its priority
  list_insert_ordered (&ready_list, &t->elem,
                            thread_priority_less_func, NULL);

  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void)
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void)
{
  struct thread *t = running_thread ();

  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void)
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void)
{
  ASSERT (!intr_context ());
#ifdef USERPROG
  struct thread *cur_thread = thread_current();
  struct list *children = &cur_thread->child_processes;
  struct list_elem *ce;

  for (ce = list_begin(children); ce != list_end(children);
       ce = list_next(ce))
  {
    struct thread *child_process = list_entry(ce, struct thread, elem);

    if (child_process->exited) {
      sema_up(&child_process->sema_exit);

    } else {
      child_process->parent = NULL;
      list_remove(ce);

    }
  }

  process_exit ();
#endif
  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  //printf("trololol");
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim.  */
void
thread_yield (void)
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());

  old_level = intr_disable ();
  // Insert yielding thread in terms of its priority
  if (cur != idle_thread)
    list_insert_ordered (&ready_list, &cur->elem,
                         thread_priority_less_func, NULL);

  cur->status = THREAD_READY;

  schedule ();
  intr_set_level (old_level);
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{

  lock_acquire(&set_priority_lock);
  thread_current ()->priority = new_priority;
  lock_release(&set_priority_lock);

  /* Yields if thread no longer has highest priority */
  yield_for_highest();
}

/* Returns the current thread's true priority.*/
int
thread_get_priority (void)
{
  return total_priority(thread_current());
}

/* Recalculates and sets the current thread t's priority */
static void
thread_recalculate_priority (struct thread *t)
{
  ASSERT(thread_mlfqs);

  /* Calculation for priority rounded down to nearest value */
  int32_t fp_pri_max    = conv_int_to_fixed(PRI_MAX);
  int32_t fp_recent_cpu = div_fixed_by_int(t->recent_cpu, 4);
  int32_t fp_nice       = conv_int_to_fixed(t->nice_value * 2);
  int32_t fp_priority   = sub_fixed_from_fixed(sub_fixed_from_fixed(fp_pri_max,
                                                        fp_recent_cpu),fp_nice);
  int int_priority      = conv_fixed_to_int_round_to_nearest(fp_priority);

  /* Adjust priority to lie in valid range PRI_MIN to PRI_MAX */
  if (int_priority > PRI_MAX) int_priority = PRI_MAX;
  if (int_priority < PRI_MIN) int_priority = PRI_MIN;

  t->priority = int_priority;
}

/* Returns the highest priority of any thread that is either running or in
   ready_list */
static int
get_highest_priority(void) {
  /* Initially sets the highest priority as the running thread's priority */
  int highest_priority = thread_get_priority();

  if (!list_empty(&ready_list)) {
    /* If there are threads ready to run in ready list, the head of the list
       has the highest priority in the list (as ready_list is ordered). */
    struct list_elem *e = list_front(&ready_list);
    struct thread *t = list_entry (e, struct thread, elem);
    int t_true_priority = total_priority(t);

    /* The head of the ready list has the highest priority if it is greater
       than the running thread's priority */
    if (t_true_priority > highest_priority)
      highest_priority = t_true_priority;
  }

  return highest_priority;
}

/* Returns true iff the current thread has the highest priority */
static bool
is_highest_priority(void)
{
  return thread_get_priority() >= get_highest_priority();
}

/* Yields current thread iff their is a higher priority thread waiting to run */
void
yield_for_highest(void)
{
  if (!is_highest_priority())
    thread_yield();
}

/* Sets the current thread's nice value to the 'nice' parameter and recalculates
   the thread's priority. Thread yields if it no longer has the
   highest priority. */
void
thread_set_nice (int nice)
{
  ASSERT(thread_mlfqs);
  ASSERT(nice <= NICE_MAX);
  ASSERT(nice >= NICE_MIN);

  /* Set current threads nice value to nice */
  thread_current()->nice_value = nice;

  /* Recalculate current threads priority */
  thread_recalculate_priority(thread_current());

  /* Yield if running thread no longer has highest priority */
  yield_for_highest();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void)
{
  ASSERT(thread_mlfqs);
  return thread_current()->nice_value;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void)
{
  ASSERT(thread_mlfqs);
  int32_t fp_load_avg = mul_fixed_by_int(load_avg, 100);
  return conv_fixed_to_int_round_to_nearest(fp_load_avg);
}

/* Recalculates and sets the value for the system load average */
static void
thread_recalculate_load_avg ()
{
  ASSERT(thread_mlfqs)
  int32_t load_avg_coeff = div_fixed_by_int(conv_int_to_fixed(59), 60);
  int32_t ready_threads_coeff = div_fixed_by_int(conv_int_to_fixed(1), 60);
  int ready_threads = list_size(&ready_list);

  /* Check type of current thread */
  if (thread_current() != idle_thread) ready_threads++;

  load_avg = add_fixed_to_fixed(mul_fixed_by_fixed(load_avg_coeff, load_avg),
                       mul_fixed_by_int(ready_threads_coeff, ready_threads));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void)
{
  ASSERT(thread_mlfqs);
  int32_t fp_recent_cpu = mul_fixed_by_int(thread_current()->recent_cpu, 100);
  return conv_fixed_to_int_round_to_nearest(fp_recent_cpu);
}

/* Recalculate and set the recent_cpu for current thread */
static void
thread_recalculate_recent_cpu(struct thread *t)
{
  ASSERT(thread_mlfqs);
  int32_t fp_load_avg = mul_fixed_by_int(load_avg, 2);
  int32_t recent_cpu_coeff = div_fixed_by_fixed(fp_load_avg,
                                              add_fixed_to_int(fp_load_avg, 1));
  t->recent_cpu = add_fixed_to_int(mul_fixed_by_fixed(recent_cpu_coeff, t->recent_cpu),
                                   t->nice_value);
}

/* Used to call thread_recalculate_recent_cpu on t with an unused aux variable
  used by thread_foreach */
static void
recalculate_recent_cpu_foreach(struct thread *t, void * unused UNUSED) {
  thread_recalculate_recent_cpu(t);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED)
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;)
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux)
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void)
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority, int nice_value)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->nice_value = nice_value;
  t->recent_cpu = 0;

  if (!thread_mlfqs) list_init(&t->donations);
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);

  #ifdef USERPROG
  sema_init (&t->sema_wait, 0);
  sema_init (&t->sema_exit, 0);

  list_init(&t->child_processes);

  list_init(&t->open_files);
  #endif

  #ifdef VM
  list_init(&t->mmap_files);
  #endif

  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size)
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread.

   The thread returned must have the highest priority (which comes from the
   front of the ordered ready_list ordered in terms of priority) */
static struct thread *
next_thread_to_run (void)
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();

  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread)
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void)
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);

  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void)
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

/* Comparator function that returns true if the thread A has higher priority
  than thread B*/
bool
thread_priority_less_func(const struct list_elem *a,
                       const struct list_elem *b, void *aux UNUSED)
{
  struct thread *a_thread = list_entry(a, struct thread, elem);
  struct thread *b_thread = list_entry(b, struct thread, elem);

  return total_priority(a_thread) > total_priority(b_thread);
}

/* Comparator function that returns true if the donation A has higher
   donated_priority than donation B*/
static bool
donation_less_func(const struct list_elem *a,
                       const struct list_elem *b, void *aux UNUSED)
{
  ASSERT(!thread_mlfqs);
  struct donation *a_donation = list_entry(a, struct donation, elem);
  struct donation *b_donation = list_entry(b, struct donation, elem);

  return a_donation->priority_donated > b_donation->priority_donated;
}

/* Returns the true priority of thread t. */
int
total_priority(struct thread *t) {
  int true_priority;

  /* If the thread has donations, the highest donated value is used as the true
     priority. If not the the threads priority is used */
  if (!thread_mlfqs && has_donations(t)) {
    struct list_elem *e = list_front(&t->donations);
    struct donation *highest_donation = list_entry (e, struct donation, elem);

    true_priority = highest_donation->priority_donated;
  } else {
    true_priority = t->priority;
  }

  return true_priority;
}

/* Returns true iff the thread t has donations */
static bool
has_donations(struct thread *t) {
  ASSERT(!thread_mlfqs);
  return !list_empty(&t->donations);
}

/* The current thread gives the thread within the lock a donation to increase
   its true priority to match the current thread */
void
donate(struct donation *d, struct lock *lock) {
  ASSERT(!thread_mlfqs);
  init_donation(d, lock, thread_current());
  add_donation(d);
}

/* Initialises a new donation made by the donor thread for the lock donor_lock*/
void
init_donation(struct donation *d, struct lock *donor_lock,
  struct thread *donor) {
  ASSERT(!thread_mlfqs);

  d->donor = donor;
  d->priority_donated = total_priority(d->donor);
  d->donor_lock = donor_lock;
}

/* Adds a new donation to the thread who has the lock associated with the
   donations */
static void
add_donation(struct donation *new_donation) {
     ASSERT(!thread_mlfqs);
     struct lock *lock = new_donation->donor_lock;
     struct thread *thread_in_lock = lock->holder;

     /* Insert the new donation to the threads list of donations in order of the
     priority_donated. Interrupts have been disabled to avoid race conditions
     on the shared donation list  */
     enum intr_level old_level;
     old_level = intr_disable ();

     list_insert_ordered (&thread_in_lock->donations, &new_donation->elem,
                               donation_less_func, NULL);

     /* Now thread_in_lock has a new donation, its true_priority may have been
        altered. Hence if it is in any list of waiters (E.g. lock or semaphore
        waiting list) then the list needs to be resorted to keep the order */
     update_wait_list(thread_in_lock);

     intr_set_level (old_level);

     /* if thread_in_lock is waiting on a different lock, it will provide it
     update the donation it gave the holder */
     if (thread_in_lock->wait_lock != NULL)
        update_donation(thread_in_lock->wait_lock, thread_in_lock);
}

/* Updates the donation made to the lock by the donor. If the lock is NULL then
   the function is exited immediately */
static void
update_donation(struct lock *lock, struct thread *donor) {
  ASSERT(!thread_mlfqs);
  if (lock == NULL) return;

  struct thread *thread_in_lock = lock->holder;
  get_donor_donation(lock, donor)->priority_donated = total_priority(donor);

  /* Now thread_in_lock has a new donation, its true_priority may have been
     altered. Hence if it is in any list of waiters (E.g. lock or semaphore
     waiting list) then the list needs to be resorted to keep the order */
  enum intr_level old_level;
  old_level = intr_disable ();

  update_wait_list(thread_in_lock);

  intr_set_level (old_level);

  /* If the thread in the lock is itself waiting on other locks, it updates the
     donations it has made */
  update_donation(thread_in_lock->wait_lock, thread_in_lock);
}

/* Resorts (in terms of true priority) the list of waiters in the thread t's
   lock and semaphore waiting lists. Interrupts must be disabled before
   calling this function */
static void
update_wait_list(struct thread *t) {
  ASSERT (intr_get_level () == INTR_OFF);

  struct lock *wait_lock = t->wait_lock;
  if (wait_lock != NULL)
     list_sort(lock_waiting_list(wait_lock),
                                 thread_priority_less_func, NULL);

  struct semaphore *wait_sema = t->wait_sema;
  if (wait_sema != NULL)
      list_sort(&wait_sema->waiters,
               thread_priority_less_func, NULL);
}

/* Returns donation made to lock by the donor */
static struct donation *
get_donor_donation(struct lock *lock, struct thread *donor) {
  ASSERT(!thread_mlfqs);
  struct list *donations = &lock->holder->donations;

  enum intr_level old_level;
  old_level = intr_disable ();

  struct list_elem *e;
  for (e = list_begin (donations); e != list_end (donations);
     e = list_next (e))
  {
    struct donation *d = list_entry (e, struct donation, elem);

    if (d->donor == donor) {
      return d;
    }

  }

  intr_set_level (old_level);
  return NULL;
}

/* Releases all donations associated with the lock */
void
remove_donations(struct lock *lock) {
  ASSERT(!thread_mlfqs);
  enum intr_level old_level;
  old_level = intr_disable ();

  struct list *donations = &thread_current()->donations;

  struct list_elem *e;
  for (e = list_begin (donations); e != list_end (donations);
       e = list_next (e))
    {
      struct donation *donation = list_entry (e, struct donation, elem);

      if (donation->donor_lock == lock) {
        list_remove(e);
      }

    }
  intr_set_level (old_level);
}

/* Returns the thread with the given thread id */
struct thread *
thread_by_tid(tid_t tid) {

  // TODO do we need to make this thread safe??
  struct list_elem *e;

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      if (t->tid == tid)
        return t;
    }
  return NULL;
}
