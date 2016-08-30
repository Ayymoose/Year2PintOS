#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

#define MAX_ARGUMENT_LENGTH 20
#define MAX_ARGS_SIZE 4096
#define WORD_SIZE 4

tid_t process_execute (const char *cmd_line);
int num_tokens(const char *str);
int push_arguments(char *file_name, char *arguments, void **esp);
void push_arg(char *arg, void **esp);
void push_byte(void **esp);
void push_arg_ptr(char **arg_ptr, void **esp);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /*userprog/process.h*/
