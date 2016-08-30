#include "threads/malloc.h"
#include "threads/synch.h"
#include "vm/mmap.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "page.h"

struct hash mmap_table;        /* Memory mapped files hash table */
struct lock mmap_table_lock;   /* Lock to ensure syncronous access */

static void destroy_mmap_entry(struct hash_elem *he, void *aux UNUSED);
static unsigned mmap_hash (const struct hash_elem *he, void *aux UNUSED);
static bool mmap_hash_less (const struct hash_elem *hea, const struct hash_elem *heb,
               void *aux UNUSED);


/* Initialises the mmap hash table and the corresponding lock */
void
init_mmap_table()
{
  lock_init (&mmap_table_lock);
  hash_init (&mmap_table, mmap_hash, mmap_hash_less, NULL);
}

/* Destroys the frame table and all allocated memory stored within it */
void
destroy_mmap_table()
{
  hash_destroy (&mmap_table, destroy_mmap_entry);
}

/* Frees up memory used up by mmap entry */
static void
destroy_mmap_entry(struct hash_elem *he, void *aux UNUSED)
{
  struct mmap_entry *me = hash_entry (he, struct mmap_entry, helem);
  free(me);
}


/* === HASH FUNCTIONS ======================================================= */

/* Returns a hash value for a mmap entry m. */
static unsigned
mmap_hash (const struct hash_elem *he, void *aux UNUSED)
{
  const struct mmap_entry *m = hash_entry (he, struct mmap_entry, helem);
  return hash_int ((unsigned) m->map_id);
}


/* Returns true if a mmap entry a preceeds mmap entry b. */
static bool
mmap_hash_less (const struct hash_elem *hea, const struct hash_elem *heb,
               void *aux UNUSED)
{
  const struct mmap_entry *a = hash_entry (hea, struct mmap_entry, helem);
  const struct mmap_entry *b = hash_entry (heb, struct mmap_entry, helem);

  return a->map_id < b->map_id;
}


/* === MMAP TABLE MANAGER FUNCTIONS ========================================== */

/* Creates and inserts a new mapped page into the mmap hash table */
void
insert_mmap(uint32_t map_id, int fd, void *vaddr_begin, void *vaddr_end)
{
  struct mmap_entry *new_me = malloc(sizeof(struct mmap_entry));
  new_me->map_id = map_id;
  new_me->fd = fd;
  new_me->vaddr_begin = vaddr_begin;
  new_me->vaddr_end = vaddr_end;

  /* Insert new mmap entry into hash table */
  lock_acquire (&mmap_table_lock);
  hash_insert (&mmap_table, &new_me->helem);
  lock_release (&mmap_table_lock);

  /* Insert into current threads list of mapped files */
  list_push_back(&thread_current()->mmap_files, &new_me->thread_elem);
}


/* Find and returns the mmap entry with the given map id */
struct mmap_entry *
find_mmap_entry(mapid_t map_id) {
  struct mmap_entry me;
  struct hash_elem *he;

  me.map_id = map_id;

  lock_acquire(&mmap_table_lock);
  he = hash_find(&mmap_table, &me.helem);
  lock_release(&mmap_table_lock);

  if (he == NULL)
    return NULL;

  struct mmap_entry *found_me = hash_entry (he, struct mmap_entry, helem);

  return found_me;
}

/* Deletes the mmap entry */
bool
delete_mmap_entry(mapid_t map_id) {

  struct mmap_entry *me = find_mmap_entry(map_id);

  if (me == NULL)
    return false;

  lock_acquire(&mmap_table_lock);
  hash_delete(&mmap_table, &me->helem);
  list_remove(&me->thread_elem);
  free(me);
  lock_release(&mmap_table_lock);
  return true;
}

/* Returns a new unused map id */
uint32_t
generate_mapid (void)
{
  static uint32_t new_mapid = 1;
  return new_mapid++;
}
