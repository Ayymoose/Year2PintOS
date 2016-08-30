#include "page.h"
#include "lib/string.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include "swap.h"
#include "frame.h"

struct lock load_lock;

/* Supplemental table hash functions */
static unsigned page_hash  (const struct hash_elem *he, void *aux UNUSED);
static bool page_hash_less (const struct hash_elem *hea,
                            const struct hash_elem *heb, void *aux UNUSED);

static void insert_supp_table(struct page *p);

/* Load functions for specific types of pages */
static bool load_file_page_frame(void *paddr, struct page *p);
static void load_zero_page_frame(void *paddr);
static void load_swap_page_frame(void *paddr, struct page *p);
static void link_page_frame(void *paddr, struct page *p);

/* Initialises global variables for page.c */
void init_global_page_load() {
  lock_init(&load_lock);
  lock_init(&sc_lock);
}

/* Initialises the supplemental page hash and the corresponding lock */
void init_supp_page_table(struct hash *supp_pt, struct lock *supp_pt_lock) {
  lock_init (supp_pt_lock);
  hash_init (supp_pt, page_hash, page_hash_less, NULL);
}

/* === PAGE CREATION ======================================================== */

/* Creates a files page */
struct page *create_file_page(void *vaddr, struct file *file, size_t offset,
                              size_t read_bytes, bool writable, off_t block_id)
{
    struct page *new_p = malloc(sizeof(struct page));

    if (new_p  != NULL) {
      new_p->vaddr = vaddr;
      new_p->writable = writable;
      new_p->in_frame = false;
      new_p->status = PAGE_FILE;
      new_p->pagedir = thread_current()->pagedir;

      new_p->fdata.file = file;
      new_p->fdata.offset = offset;
      new_p->fdata.read_bytes = read_bytes;
      new_p->fdata.block_id = block_id;

      new_p->swap_index = 0;

      insert_supp_table(new_p);
    }

    return new_p;
}

/* Creates a zero page */
struct page *create_zero_page(void *vaddr) {
  struct page *new_p = malloc(sizeof(struct page));

  if (new_p  != NULL) {
    new_p->vaddr = vaddr;
    new_p->writable = true;
    new_p->in_frame = false;
    new_p->status = PAGE_ZERO;
    new_p->pagedir = thread_current()->pagedir;

    new_p->swap_index = 0;

    insert_supp_table(new_p);
  }

  return new_p;
}


/* == PAGE LOADING ========================================================== */

/* Loads the page at vaddr into memory. Returns true iff the page was
   successfully loaded into memory */
bool load_page(void *vaddr) {
  /* Get page from current threads supp table */
  struct page *p = find_page(vaddr);

  /* If no page was created for vaddr then fail load */
  if (p == NULL)
    return false;

  void *paddr = page_paddr(p);

  /* If the page is already loaded in memory return */
  if (paddr != NULL)
    return true;

  lock_acquire(&load_lock);

    /* Finds a frame for the page p */
    paddr = find_suitable_frame(p);

    ASSERT(is_kernel_vaddr(paddr));

    /* If the frame was not free prior to linking (marrying) the frame with the
      page, it means the frame has to be shared */
    bool is_frame_shared = false;
    if (!is_frame_paddr_free(paddr))
      is_frame_shared = true;

    /* Link page with frame. Page now married to frame */
    link_page_frame(paddr, p);

  lock_release(&load_lock);

  /* If frame is already in memory then do not reload it (sharing) */
  if(is_frame_shared) {
    allow_eviction(paddr);
    return true;
  }

  ASSERT(!find_frame(paddr)->evictable);

  if (p->status == PAGE_FILE) {
    if (!load_file_page_frame(paddr, p))
      return false;

  } else if (p->status == PAGE_ZERO) {
    load_zero_page_frame(paddr);

  } else if (p->status == PAGE_SWAP) {
    load_swap_page_frame(paddr, p);

  }

  pagedir_set_dirty (p->pagedir, p->vaddr, false);
  pagedir_set_accessed (p->pagedir, p->vaddr, true);

  allow_eviction(paddr);

  return true;

}

/* Links a page and a frame together (Used for loading page). Marry p and f*/
static void link_page_frame(void *paddr, struct page *p) {
  /* Adds entry to p's pagedir for p and paddr */
  page_set_paddr(p, paddr);
  /* Adds page to new frames list of pages */
  frame_add_page(paddr, p);
  /* Page now connected to frame */
  p->in_frame = true;
  /* Add page to list of in memory pages used for eviction */
  lock_acquire(&sc_lock);
  list_push_back(&in_mem_pages, &p->sc_elem);
  lock_release(&sc_lock);
}

/* Loads a page into the frame with paddr. Reads read_bytes from the page
   and sets the remaining bytes to 0. Returns true iff the page was
   loaded successfully */
static bool load_file_page_frame(void *paddr, struct page *p) {
  bool had_lock_before = false;
  if (!lock_held_by_current_thread(&file_system_lock))
    lock_acquire(&file_system_lock);
  else
    had_lock_before = true;

  file_seek(p->fdata.file, p->fdata.offset);
  size_t ret = file_read(p->fdata.file, paddr, p->fdata.read_bytes);

  if (!had_lock_before)
    lock_release(&file_system_lock);

  if (ret != p->fdata.read_bytes)
      return false;

  /* Zero the rest of the page */
  memset (paddr + p->fdata.read_bytes, 0, PGSIZE - p->fdata.read_bytes);

  struct frame_entry *fe = find_frame(paddr);
  lock_acquire(&fe->frame_lock);
  fe->offset = p->fdata.offset;
  fe->block_id = p->fdata.block_id;
  lock_release(&fe->frame_lock);

  return true;
}

/* Zero's a whole page */
static void load_zero_page_frame(void *paddr) {
  memset (paddr, 0, PGSIZE);
}

/* Loads a page from the swap with paddr into main memory and frees
   the underlying swap slot. */
static void load_swap_page_frame(void *paddr, struct page *p) {
  swap_table_load (paddr, p->swap_index);

  p->status = p->prev_status;
  p->swap_index = 0;
}


/* === SUP TABLE MANAGER FUNCTIONS ====================================== */

/* Inserts page into current threads supp table */
static void insert_supp_table(struct page *p) {
  struct thread *curr = thread_current();

  lock_acquire(&curr->supp_page_table_lock);
  hash_insert(&curr->supp_page_table, &p->helem);
  lock_release(&curr->supp_page_table_lock);
}

/* Finds a page associated with the vaddr in the current threads supp table */
struct page *find_page(void *vaddr) {
  struct thread *curr = thread_current();
  struct page p;
  struct hash_elem *he;

  p.vaddr = vaddr;

  lock_acquire (&curr->supp_page_table_lock);
  he = hash_find (&curr->supp_page_table, &p.helem);
  lock_release (&curr->supp_page_table_lock);

  if (he == NULL)
    return NULL;

  struct page *found_p = hash_entry (he, struct page, helem);

  return found_p;
}

/* If page p is in memory, returns physical address to p's frame */
void *page_paddr(struct page *p) {
  return pagedir_get_page (p->pagedir, p->vaddr);
}

/* Add page table entry for addresses */
bool page_set_paddr(struct page *p, void *paddr) {
  return pagedir_get_page (p->pagedir, p->vaddr) == NULL &&
         pagedir_set_page (p->pagedir, p->vaddr, paddr, p->writable);
}

/* Returns true iff the page has been written to */
bool page_used(struct page *p) {
  return pagedir_is_dirty (p->pagedir, p->vaddr);
}

/* === HASH FUNCTIONS =================================================== */

/* Returns a hash value for a page entry pe. */
static unsigned
page_hash (const struct hash_elem *he, void *aux UNUSED)
{
  const struct page *p = hash_entry (he, struct page, helem);
  return hash_int ((unsigned) p->vaddr);
}

/* Returns true if a page a preceeds page b. */
static bool
page_hash_less (const struct hash_elem *hea, const struct hash_elem *heb,
               void *aux UNUSED)
{
  const struct page *a = hash_entry (hea, struct page, helem);
  const struct page *b = hash_entry (heb, struct page, helem);

  return a->vaddr < b->vaddr;
}

/* Destroys the supplemental page table */
void destroy_supp_page_table(struct hash *supp_pt) {
  hash_destroy (supp_pt, destroy_page);
}

/* Frees up memory used up by frame entry
   Removes the page associated with the frame */
void destroy_page(struct hash_elem *he, void *aux UNUSED) {
  /* Find the page in the page table */
  struct page *p = hash_entry (he, struct page, helem);

  if (!write_back_frame_file(find_frame(page_paddr(p)))) {
    /* Remove the page from the list of frames (divorce the frame) */
    frame_remove_page(page_paddr(p),p);
  }

  /* Free the page */
  free(p);
}

/* Destroys a page and removes page from list of frames */
void page_destroy(struct page *p) {
  struct thread *cur = thread_current();

  ban_eviction(page_paddr(p));

  if (!write_back_frame_file(find_frame(page_paddr(p)))) {
    /* Remove the page from the list of frames (divorce the frame) */
    frame_remove_page(page_paddr(p),p);
  }

  lock_acquire(&cur->supp_page_table_lock);
  hash_delete(&cur->supp_page_table, &p->helem);
  lock_release(&cur->supp_page_table_lock);

  /* Free the page */
  free(p);
}
