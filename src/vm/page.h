#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <stdio.h>
#include "filesys/off_t.h"
#include "threads/synch.h"

enum page_status {
  PAGE_SWAP,     /* Page is swap disk */
  PAGE_FILE,     /* Page containing file data */
  PAGE_MEM_FILE, /* Page containing memory mapped file */
  PAGE_ZERO      /* Page that needs to be initialised to zero */
};

/* If the page contains a file, then this struct contains information about what
   bytes within the file is within the page */
struct file_data {
  struct file *file;
  size_t offset;    /* offset into file */
  size_t read_bytes;/* Number of bytes from file in page */
  off_t block_id;   /* Used to uniquely identify a specific block used by the
                       file (Used by frames for sharing) */
};

struct page {
  void *vaddr;             /* Virtual address for page */
  bool writable;           /* True iff page is writable */
  bool in_frame;           /* True iff the page is loaded in a frame */
  enum page_status status; /* Page status of page */

  struct hash_elem helem;  /* Hash element */
  struct list_elem elem;   /* List element */
  struct list_elem sc_elem;/* Second chance eviction list element */

  uint32_t *pagedir;       /* Page directory the page is within */

  struct file_data fdata;

  size_t swap_index;       /* Page's swap index if page is in swap space */
  enum page_status prev_status; /* If page swapped, contains previous status */
};

struct lock sc_lock;  /* Page lock used during second chance eviction */

void init_global_page_load(void);
void init_supp_page_table(struct hash *supp_pt, struct lock *supp_pt_lock);
void destroy_supp_page_table(struct hash *supp_pt);

struct page *create_zero_page(void *vaddr);
struct page *create_file_page(void *vaddr, struct file *file, size_t offset,
                              size_t read_bytes, bool writable, off_t block_id);

bool load_page(void *vaddr);

void *page_paddr(struct page *p);
bool page_set_paddr(struct page *p, void *paddr);
bool page_used(struct page *p);

struct page *find_page(void *vaddr);
void destroy_page(struct hash_elem *he, void *aux UNUSED);
void page_destroy(struct page *p);

#endif
