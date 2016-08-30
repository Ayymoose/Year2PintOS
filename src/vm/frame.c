#include "frame.h"
#include "swap.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/vaddr.h"

/* Frame table hash functions */
static unsigned frame_hash (const struct hash_elem *he, void *aux UNUSED);
static bool frame_hash_less (const struct hash_elem *hea,
                                 const struct hash_elem *heb, void *aux UNUSED);
static void init_frame_entry(struct frame_entry *fe, void *paddr);
static void destroy_frame_entry(struct hash_elem *he, void *aux UNUSED);
static bool is_frame_free(struct frame_entry *fe);
static void *find_free_frame(void);
static void *find_frame_with_blockid(off_t block_id, size_t offset);
static void reset_frame_entry(struct frame_entry *fe);

/* Second chance eviction algorithm functions */
static void ban_eviction_fe(struct frame_entry *fe);
static void allow_eviction_fe(struct frame_entry *fe);
static void *eviction(void);
static void evict_frame(struct frame_entry *fe);
static void *random_eviction(void);
static void *second_chance_eviction(void);
static void advance_curr_pointer(void);

struct hash frame_table;  /* Frame table hash map */
struct lock ft_lock;      /* Lock on frame table */
struct lock evict_lock;   /* Lock for eviction */
struct lock unload_lock;  /* Lock for unloading a page */


/* == FRAME ALLOCATION ====================================================== */

/* Initialises the frame table and associated locks and lists */
void
init_frame_table() {
  lock_init (&ft_lock);
  lock_init (&evict_lock);
  lock_init (&unload_lock);
  list_init (&in_mem_pages);
  hash_init (&frame_table, frame_hash, frame_hash_less, NULL);
}

/* Returns a new physical address for a new frame which is created */
void *
frame_alloc(enum palloc_flags flags, bool locked) {
  void *paddr = palloc_get_page(flags);

  if (paddr != NULL) {
    struct frame_entry *new_fe = malloc(sizeof(struct frame_entry));

    if (new_fe == NULL) {
      ASSERT(false);
      palloc_free_page(paddr);
      return NULL;
    }

    init_frame_entry(new_fe, paddr);
    new_fe->locked = locked;

    lock_acquire (&ft_lock);
    hash_insert (&frame_table, &new_fe->helem);
    lock_release (&ft_lock);

    ASSERT(!new_fe->evictable);

  } else {
    #ifndef VM
      exit(-1);
    #endif

    paddr = eviction();
    struct frame_entry *evicted_fe = find_frame(paddr);
    evicted_fe->locked = locked;
  }

  ASSERT(is_kernel_vaddr(paddr));
  ASSERT(find_frame(paddr)->locked == locked);
  return paddr;
}

/* Intialises frame entry */
static void
init_frame_entry(struct frame_entry *fe, void *paddr) {
  fe->paddr = paddr;
  fe->evictable = false;

  fe->block_id = -1;
  fe->offset= 0;

  fe->locked = false;
  list_init (&fe->pages);
  lock_init (&fe->frame_lock);
}

/* Resets fields of frame */
static void
reset_frame_entry(struct frame_entry *fe) {
  ASSERT(is_frame_free(fe));

  fe->block_id = -1;
  fe->offset = 0;
  fe->locked = false;
  fe->evictable = false;
}

/* Destroy frame table and all allocated memory stored within it */
void
destroy_frame_table() {
  hash_destroy (&frame_table, destroy_frame_entry);
}

/* Finds and returns a frame for the page p based on:
   1: If the page contains a read-only file block which has a frame, return the
      address of such frame
   2: If the page is not connected to any frame, find an unused frame
   3: If no frame is available allocate a new one with frame_alloc */
void *
find_suitable_frame(struct page *p) {
  void *paddr = NULL;

  if (p->status == PAGE_FILE && !p->writable) {
    paddr = find_frame_with_blockid(p->fdata.block_id, p->fdata.offset);
    ban_eviction(paddr);

    /* If frame with block id is found, return its paddr */
    if (paddr != NULL)
      return paddr;
  }

  /* Check if any frames are free */
  paddr = find_free_frame();

  /* If we found a free frame return its paddr*/
  if (paddr != NULL) {
    ASSERT(!find_frame(paddr)->evictable);
    return paddr;
  }

  /* If no frames are free we have to allocate a new one.
     Note if allocation fails, a frame will be evicted */
  return frame_alloc(PAL_USER, false);
}

/* Frees up memory used up by frame entry */
static void
destroy_frame_entry(struct hash_elem *he, void *aux UNUSED) {
  struct frame_entry *fe = hash_entry (he, struct frame_entry, helem);

  lock_acquire(&fe->frame_lock);
  while(!list_empty(&fe->pages)) {
    struct page *p = list_entry(list_begin(&fe->pages), struct page, elem);

    /* Unmap the page from its page table (Divorce page from frame) */
    pagedir_clear_page(p->pagedir, p->vaddr);

    /* Page is no longer in the frame */
    p->in_frame = false;

    /* Removed page from its frame */
    list_remove(&p->elem);
  }
  lock_release(&fe->frame_lock);

  ASSERT(list_empty(&fe->pages));

  palloc_free_page(fe->paddr);
  free(fe);
}

/* Frees memory used by frame entry */
void
frame_free(void *paddr) {
  struct frame_entry *fe = find_frame(paddr);

  lock_acquire(&ft_lock);
  hash_delete(&frame_table, &fe->helem);
  lock_release(&ft_lock);

  palloc_free_page(fe->paddr);
  free(fe);
}

/* == FRAME TABLE MANAGER =================================================== */

/* Checks whether a frame is being used by any pages */
static bool
is_frame_free(struct frame_entry *fe) {
  if (fe == NULL)
    return false;

  lock_acquire(&fe->frame_lock);
  bool result = list_empty(&fe->pages) && !fe->locked;
  lock_release(&fe->frame_lock);

  return result;
}

/* Wrapper for is_frame_free */
bool
is_frame_paddr_free(void *paddr) {
  struct frame_entry *fe = find_frame(paddr);
  return is_frame_free(fe);
}

/* Traverses hash map and returns the paddr of any free frame found */
static void *
find_free_frame() {
  struct hash_iterator i;

  lock_acquire(&ft_lock);

  hash_first (&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_entry *fe = hash_entry(hash_cur(&i), struct frame_entry, helem);
    if (is_frame_free(fe)) {
      lock_release(&ft_lock);
      return fe->paddr;
    }
  }

  lock_release(&ft_lock);

  return NULL;
}

/* If a frame has been allocated for the given block id then return the frame's
   paddr */
static void *
find_frame_with_blockid(off_t block_id, size_t offset) {
  struct hash_iterator i;

  lock_acquire(&ft_lock);

  hash_first (&i, &frame_table);
  while (hash_next(&i)) {
    struct frame_entry *fe = hash_entry(hash_cur(&i), struct frame_entry, helem);
    if (fe->block_id == block_id && fe->offset == offset &&
        is_frame_read_only(fe)) {
      lock_release(&ft_lock);
      return fe->paddr;
    }

  }

  lock_release(&ft_lock);

  return NULL;
}

/* Adds page to frames page list */
bool
frame_add_page (void *paddr, struct page *p)
{
  struct frame_entry *fe = find_frame(paddr);

  if (fe == NULL || p == NULL)
    return false;

  lock_acquire (&fe->frame_lock);
  list_push_back (&fe->pages, &p->elem);
  lock_release (&fe->frame_lock);
  return true;
}

/* Removes page from frames page list */
bool
frame_remove_page (void *paddr, struct page *p)
{

  struct frame_entry *fe = find_frame(paddr);

  if (fe == NULL || p == NULL || page_paddr(p) != paddr)
    return false;

  ban_eviction_fe(fe);

  lock_acquire (&fe->frame_lock);
  list_remove (&p->elem);
  lock_release (&fe->frame_lock);

  if (is_frame_free(fe)) {
    fe->block_id = -1;
    fe->offset = 0;
  }

  allow_eviction_fe(fe);

  return true;
}

/* Finds a frame attached to the physical address paddr */
struct frame_entry *
find_frame(void *paddr) {
  if (paddr == NULL)
    return NULL;

  struct frame_entry fe;
  struct hash_elem *he;

  fe.paddr = paddr;

  lock_acquire (&ft_lock);
  he = hash_find (&frame_table, &fe.helem);
  lock_release (&ft_lock);

  if (he == NULL)
    return NULL;

  struct frame_entry *found_fe = hash_entry (he, struct frame_entry, helem);

  return found_fe;
}

/* If the page using the frame is read only return true (Frame can be shared) */
bool
is_frame_read_only(struct frame_entry *fe) {
  lock_acquire(&fe->frame_lock);
  struct page *page_in_frame
    = list_entry(list_begin(&fe->pages), struct page, elem);
  lock_release(&fe->frame_lock);

  if (page_in_frame == NULL)
    return false;

  return !page_in_frame->writable;
}

/* If the page using the frame is dirty, return true */
bool
is_frame_dirty(struct frame_entry *fe) {
  lock_acquire(&fe->frame_lock);
  struct page *page_in_frame
    = list_entry(list_begin(&fe->pages), struct page, elem);
  lock_release(&fe->frame_lock);

  if (page_in_frame == NULL)
    return false;

  return page_used(page_in_frame);
}


/* == EVICTION ============================================================== */

/* Prevents frame with paddr from being evicted */
void
ban_eviction(void *paddr) {
  struct frame_entry *fe = find_frame(paddr);
  ban_eviction_fe(fe);
}

/* Allows frame with paddr to be evicted */
void
allow_eviction(void *paddr) {
  struct frame_entry *fe = find_frame(paddr);
  allow_eviction_fe(fe);
}

/* Prevents a frame entry with paddr from being evicted */
static void
ban_eviction_fe(struct frame_entry *fe) {
  if(fe == NULL)
    return;

    bool had_lock = false;
    if (!lock_held_by_current_thread(&evict_lock))
      lock_acquire(&evict_lock);
    else
      had_lock = true;

  fe->evictable = true;

  if (!had_lock)
    lock_release(&evict_lock);
}

/* Allows a frame entry with paddr to be evicted */
static void
allow_eviction_fe(struct frame_entry *fe) {
  if(fe == NULL)
    return;

  bool had_lock = false;
  if (!lock_held_by_current_thread(&evict_lock))
    lock_acquire(&evict_lock);
  else
    had_lock = true;

  fe->evictable = true;

  if (!had_lock)
    lock_release(&evict_lock);
}

/* Evicts a frame and returns its now free paddr. If a frame is already free
   before eviction begins, its paddr is returned instead */
static void *
eviction() {
  void *paddr; /* paddr of free or evicted frame */

  /* Check if there are any free frames and return one if there is */
  paddr = find_free_frame();
  if (paddr != NULL)
    return paddr;

  lock_acquire(&evict_lock);
  lock_acquire(&ft_lock);

  paddr = second_chance_eviction();

  lock_release(&ft_lock);
  lock_release(&evict_lock);

  return paddr;
}

/*Evicts the frame fe by divorcing it froms it's page and unloading if needed*/
static void
evict_frame(struct frame_entry *fe) {
  ASSERT(lock_held_by_current_thread(&evict_lock) && fe->evictable &&
         !fe->locked);

  unload_page(fe);

  ASSERT(is_frame_free(fe));
}

/* Second chance eviction algorithm */
static void *
second_chance_eviction() {
  ASSERT(lock_held_by_current_thread(&evict_lock));

  struct page *p = NULL;
  void *evicted_paddr; /* Physical address of frame that will be chosen for
                          eviction */

  while (true) {

     /* Get the next page pointed to by the pointer in the 'cyclic' list */
    if (curr_sc_elem == NULL || curr_sc_elem == list_end(&in_mem_pages))
      curr_sc_elem = list_begin(&in_mem_pages);

    p = list_entry(curr_sc_elem, struct page, sc_elem);
    struct frame_entry *frame = find_frame(page_paddr(p));

    ASSERT(frame != NULL);

    /* Check if the page is not evictable or locked */
    if (!frame->evictable || frame->locked) {
      advance_curr_pointer();
      continue;
    }

    /* Check if the accessed bit is set in which case flip it */
    if (pagedir_is_accessed(p->pagedir, p->vaddr)) {
      pagedir_set_accessed(p->pagedir, p->vaddr, false);
      advance_curr_pointer();
      continue;
    }

    /* If accessed bit is not set then evict the frame */
    if (!pagedir_is_accessed(p->pagedir, p->vaddr)) {
      evicted_paddr = frame->paddr;
      evict_frame(frame);
      break;
    }

  }

  return evicted_paddr;
}

/* Shifts the current pointer in the list of memory mapped pages in order to
   simulate a cyclic linked list */
static void
advance_curr_pointer(void) {
  if (curr_sc_elem == NULL || curr_sc_elem == list_end(&in_mem_pages)) {
    curr_sc_elem = list_begin (&in_mem_pages);
  } else {
    curr_sc_elem = list_next (curr_sc_elem);
  }
}

/* Random eviction algorithm */
static void *
random_eviction() {
  ASSERT(lock_held_by_current_thread(&evict_lock));
  struct hash_iterator i;

  hash_first (&i, &frame_table);
  while (hash_next(&i)) {

    struct frame_entry *fe
      = hash_entry(hash_cur(&i), struct frame_entry, helem);

    if (!fe->locked && fe->evictable) {
      evict_frame(fe);
      return fe->paddr;
    }

  }

  return NULL;
}

/* Unloads a page from its frame and into the swap table if the page is dirty.
   This affectively divorces the page from its frame*/
void
unload_page(struct frame_entry *fe) {
  if (fe == NULL || is_frame_free(fe))
    return;

  /* Assume unload can only be called by eviction */
  lock_acquire(&unload_lock);

  if (write_back_frame_file(fe)) {
    lock_release(&unload_lock);
    return;
  }

  bool activate_swap = !is_frame_read_only(fe) && is_frame_dirty(fe);
  size_t swap_index = 0;

  /* If the frame has been written to, then swap it out */
  if (activate_swap)
    swap_index = swap_table_store(fe->paddr);

  lock_acquire(&fe->frame_lock);
  while(!list_empty(&fe->pages)) {
    struct page *p = list_entry(list_begin(&fe->pages),
                                            struct page, elem);

    /* Unmap the page from its page table (Divorce page from frame) */
    pagedir_clear_page(p->pagedir, p->vaddr);

    /* Page is no longer in the frame */
    p->in_frame = false;

    /* If the page was swapped, save swap info */
    if (activate_swap) {
      p->prev_status = p->status;
      p->status = PAGE_SWAP;
      p->swap_index = swap_index;
    }

    /* Removed page from its frame */
    list_remove(&p->elem);

    /* Remove the page element from the second chance list and set the current
       pointer to the next element */
    lock_acquire(&sc_lock);
    curr_sc_elem = list_remove(&p->sc_elem);
    lock_release(&sc_lock);
  }
  lock_release(&fe->frame_lock);

  /* Reinitialise frame data */
  reset_frame_entry(fe);

  lock_release(&unload_lock);
}

/* Checks if the frame contains a file block that has been written to. If so
   the file is written back into the file system. Returns true if this happend*/
bool
write_back_frame_file(struct frame_entry *fe) {
  if (fe == NULL)
    return false;

  ban_eviction_fe(fe);

  struct page *p = list_entry(list_begin(&fe->pages), struct page, elem);
  if (p->status == PAGE_FILE && pagedir_is_dirty (p->pagedir, p->vaddr))
  {
    bool had_lock = false;
    if(!lock_held_by_current_thread(&file_system_lock))
      lock_acquire(&file_system_lock);
    else
      had_lock = true;

    file_seek (p->fdata.file, p->fdata.offset);
    file_write (p->fdata.file, fe->paddr, p->fdata.read_bytes);

    if (!had_lock)
      lock_release(&file_system_lock);

    /* Removed page from its frame */
    lock_acquire(&fe->frame_lock);
    list_remove(&p->elem);
    lock_release(&fe->frame_lock);

    /* Remove the page element from the second chance list and set the current
       pointer to the next element */
    lock_acquire(&sc_lock);
    curr_sc_elem = list_remove(&p->sc_elem);
    lock_release(&sc_lock);

    /* Reinitialise frame data */
    reset_frame_entry(fe);

    /* Divorce page from frame */
    /* Unmap the page from its page table (Divorce page from frame) */
    pagedir_clear_page(p->pagedir, p->vaddr);

    /* Page is no longer in the frame */
    p->in_frame = false;

    return true;
  }

  allow_eviction_fe(fe);
  return false;
}

/* == HASH FUNCTIONS ======================================================== */

/* Returns true if a frame a preceeds frame b. */
static bool
frame_hash_less (const struct hash_elem *hea, const struct hash_elem *heb,
               void *aux UNUSED)
{
  const struct frame_entry *a = hash_entry (hea, struct frame_entry, helem);
  const struct frame_entry *b = hash_entry (heb, struct frame_entry, helem);

  return a->paddr < b->paddr;
}

/* Returns a hash value for a frame fe. */
static unsigned
frame_hash (const struct hash_elem *he, void *aux UNUSED)
{
  const struct frame_entry *fe = hash_entry (he, struct frame_entry, helem);
  return hash_int ((unsigned)fe->paddr);
}
