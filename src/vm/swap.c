#include <bitmap.h>
#include "swap.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/block.h"

/* There are SECTORS_PER_PAGE blocks per page */
#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

static struct lock swap_table_lock;     /* Lock for the swap table */
static struct block *swap_table_block;  /* Pointer to block device */
static size_t swap_table_size;          /* Size in sectors */
static struct bitmap *swap_table;       /* Bitmap used for the swap table */

/* Initialises the swap table */
void
init_swap_table(void)
{
  lock_init(&swap_table_lock);

  /* Get the block device for swapping */
  swap_table_block = block_get_role(BLOCK_SWAP);
  ASSERT(swap_table_block != NULL);

  /* Create the swap table */
  swap_table_size = block_size(swap_table_block);
  ASSERT(swap_table_size != 0);
  swap_table = bitmap_create(swap_table_size);
  ASSERT(swap_table != NULL);
}

/* Stores the page at page_address into the swap table
   Returns the index of the page of where it's stored */
size_t
swap_table_store(void *page_address)
{

  lock_acquire(&swap_table_lock);

  /* A page is divided into SECTORS_PER_PAGE blocks in the swap partition */

  /* Find SECTORS_PER_PAGE free slots in the swap table and set them as used.
     If our swap table is full then we panic the kernel */

     /* index is the index of the page in the swap table */
     size_t index = bitmap_scan_and_flip(swap_table, 0, SECTORS_PER_PAGE,false);
     if (index == BITMAP_ERROR) {
       PANIC("Swap space exhausted");
     }

     /* Write each sector of the page to the swap partition */
     /* Each sector holds BLOCK_SECTOR_SIZE bytes so we write PGSIZE bytes to
        the swap partition in blocks */
     block_sector_t sector;
     size_t i = index;
     for (sector = 0; sector < SECTORS_PER_PAGE; sector++,i++) {

       block_write(swap_table_block, sector,
         page_address + sector * BLOCK_SECTOR_SIZE);

       /* The index must be less than the size of the swap table */
       ASSERT (i < swap_table_size);
       /* Each bit at index must be set */
       ASSERT (bitmap_test (swap_table, i) == true);
     }

  lock_release(&swap_table_lock);
  return index;
}

/* Loads the page at index in the swap table back to memory
   AND frees the slots which the page occupied */
void
swap_table_load(void *address, size_t index)
{
  lock_acquire(&swap_table_lock);

  block_sector_t sector;

  /* Read each sector of a page back into memory */
  for (sector = 0; sector < SECTORS_PER_PAGE; sector++,index++) {

    /* The index must be less than the size of the swap table */
    ASSERT (index < swap_table_size);
    /* Each bit at index must be set before we read */
    ASSERT (bitmap_test (swap_table, index) == true);

    block_read(swap_table_block, sector, address + sector * BLOCK_SECTOR_SIZE);

    /* Free the slot in the swap table */
    bitmap_reset(swap_table, index);
  }

  lock_release(&swap_table_lock);
}

/* Frees the swap table */
void
destroy_swap_table(void)
{
  bitmap_destroy(swap_table);
}
