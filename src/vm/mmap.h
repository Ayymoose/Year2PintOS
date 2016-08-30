#ifndef VM_MMAP_H
#define VM_MMAP_H

#include <stdio.h>
#include <hash.h>
#include "threads/synch.h"

typedef int mapid_t;


void init_mmap_table(void);
void destroy_mmap_table(void);
void insert_mmap(uint32_t map_id, int fd, void *vaddr_begin, void *vaddr_end);
struct mmap_entry *find_mmap_entry(mapid_t map_id);
bool delete_mmap_entry(mapid_t map_id);
uint32_t generate_mapid (void);

struct mmap_entry {
  mapid_t map_id;              /* Map region id */
  int fd;                      /* File descriptor of mapped file */
  struct hash_elem helem;      /* Hash element */
  struct list_elem thread_elem;/* List elem for a thread's mmap_file list */
  void *vaddr_begin;           /* Start of mapped file */
  void *vaddr_end;             /* End of mapped file (may span multiple pages) */
};


#endif
