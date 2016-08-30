#ifndef SWAP_H
#define SWAP_H

void init_swap_table(void);
unsigned swap_table_store(void *page_address);
void swap_table_load(void *address, size_t index);
void destroy_swap_table(void);

#endif
