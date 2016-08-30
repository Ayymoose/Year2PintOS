#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include "threads/palloc.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "page.h"

struct frame_entry {
  void *paddr;            /* Physical address to frame */
  bool evictable;         /* True iff the frame can be evicted */
  struct list pages;      /* All pages using this frame */

  off_t block_id;         /* Id of file block within the frame (default: -1) */
  size_t offset;          /* If frame contains a file block, contains offset
                             into block */

  struct lock frame_lock; /* Lock for shared access to frame  */
  struct hash_elem helem; /* Hash element */

  bool locked;            /* True iff frame can only be used by frame_alloc
                             holder */
};


struct list in_mem_pages;       /* Eviction list: A list of all pages in memory */
struct list_elem *curr_sc_elem; /* Current element being pointed to in list */

void init_frame_table(void);
void destroy_frame_table(void);
void *frame_alloc(enum palloc_flags flags, bool locked);
void frame_free(void *paddr);
bool frame_add_page (void *paddr, struct page *p);
bool frame_remove_page (void *paddr, struct page *p);
void *find_suitable_frame(struct page *p);
struct frame_entry *find_frame(void *paddr);
bool is_frame_paddr_free(void *paddr);
void allow_eviction(void *paddr);
void ban_eviction(void *paddr);
bool is_frame_read_only(struct frame_entry *fe);
bool is_frame_dirty(struct frame_entry *fe);
bool write_back_frame_file(struct frame_entry *fe);

void unload_page(struct frame_entry *fe);

#endif
