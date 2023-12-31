/* Sticks a system call number (SYS_EXIT) at the very top of the
   stack, then invokes a system call with the stack pointer
   (%esp) set to its address.  The process must be terminated
   with -1 exit code because the argument to the system call
   would be above the top of the user address space. */

#include <syscall-nr.h>
#include "tests/lib.h"
#include "tests/main.h"
#include <stdio.h>

void main (void)
{
  if (create ("quux.dat", 0))
    printf("\ncreate quux.dat\n");
}
