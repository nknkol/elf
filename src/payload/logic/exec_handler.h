#ifndef EXEC_HANDLER_H
#define EXEC_HANDLER_H

long handle_execve_like(long sys_no, long *args, int is_execveat);

#endif /* EXEC_HANDLER_H */
