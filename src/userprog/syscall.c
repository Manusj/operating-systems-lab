#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int validate_userpointers(void * data)
{
  // Checking if data adress is below physical base and checking if there is a page allocated for the data point
  if(data!=NULL && data<PHYS_BASE && (pagedir_get_page (thread_current()->pagedir, data) != NULL))
  {
      // return Valid User Pointer
      return 1;
  }
  return 0; //retrun invalid user pointer
}

// Exit the current thread  with exit code status
void exit(int status)
{
  // Update exit status of thread
  thread_current()->parent_pcs->exit_status = status;
  //Exiting current thread
  thread_exit();
}

// Validating all charater's in a string
int validate_string(char *string)
{
  do
  {
    // Check if current position in string is a valid user pointer
    if(!validate_userpointers(string))
      return 0; // returing 0 if it is a invalid data pointer
    string++; // going to next position in string
  }while(*string!='\0'); // ending loop when \0(end of string) is encountered
  return 1; // returing 1 to show it is a valid string
}

// checking if buffer is valid for the whole size give
int validate_buffer(char *buffer, int size)
{
  // iterating through the size of the buffer
  for(int i=0;i<size;i++)
  {
    // Check if current position in buffer is a valid user pointer
    if(!validate_userpointers(buffer))
      return 0; // returing 0 if it is a invalid data pointer
    buffer++; // going to next position in buffer
  }
  return 1;  // returing 1 to show it is a valid string
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  if(!validate_userpointers(f->esp)) // validating if stack pointer is valid
    exit(-1);

  int system_call_no = *(int **)(f->esp);
  //printf ("\n[SYSCALL] System call - %d, esp - %p \n ",system_call_no,f->esp);


  switch(system_call_no)
  {
    case SYS_HALT:
    {
      power_off();
      break;
    }

    case SYS_CREATE: {
      const char *file = *((char**)(f->esp+4));
      unsigned new_size = *((unsigned*)(f->esp+8));

      if(file == NULL || !validate_string(file) || !validate_userpointers(f->esp+8)) // validating if filename and size is valid
      {
        exit(-1);
        break;
      }
      bool status = filesys_create(file, new_size);
      f->eax = status;
      break;
    }

    case SYS_OPEN: {

      struct thread* current_thread = thread_current();
      const char *name = *((char**)(f->esp+4));

      if(name == NULL || !validate_string(name))  // validating if filename is valid
      {
        exit(-1);
        break;
      }

      struct file* file_obj = filesys_open(name);

      //printf("\n[SYSCALL] SYS_OPEN - Filename - %s \n", name);
      // setting return value to inavlid(-1) by default
      f->eax = -1;

      if(file_obj == NULL)
      {
        //printf("\n[SYSCALL] SYS_OPEN - file_obj is NULL \n");
        break;
      }



      int i;
      // iterating amoung all 128 avaiable slots for file descriptors and assigning the first that is free
      for (i = 0; i < 128; i++) {
        struct file** fi = &current_thread->fds[i];
          if (*fi == NULL) {
            *fi = file_obj;
            // File descriptor is returned as +2 because the 0 & 1 are used already for standard input
            f->eax = i + 2;
            break;
        }
      }
      break;
    }
    case SYS_CLOSE:
    {
      int fd = *(int **)(f->esp+4);
      struct thread* current_thread = thread_current();
      // returining -1 in case of invalid FD
      if (fd < 2 || fd > 129) {
        return -1;
      }
      // Subtracting -2 from the recived dile decriptor to get the array index
      struct file* file = current_thread->fds[fd-2];
      if (file != NULL) {
        file_close(file);
        current_thread->fds[fd-2] = NULL;
      }
      break;
    }
    case SYS_READ:
      {
        struct thread* current_thread = thread_current();
        int fd = *(int **)(f->esp+4);
        char* buffer = *(char **)(f->esp+8);
        unsigned int size = *(unsigned **)(f->esp+12);

        if(buffer == NULL || !validate_buffer(buffer, size) || !validate_userpointers(f->esp+4) || !validate_userpointers(f->esp+12))  // validating if buffer, file descriptor, size is valid
        {
          exit(-1);
          break;
        }

        // returining -1 in case of invalid FD
        if (fd < 0 || fd > 129 || fd == STDOUT_FILENO) {
          f->eax = -1;
          break;
        }

        // Reading from console in case of standard input
        if (fd == STDIN_FILENO) {
          unsigned int i;
          for (i = 0; i < size; i++) {
              buffer[i] = input_getc();
            }
            f->eax = i;
        }
        else
        {
          struct file* file = current_thread->fds[fd - 2];
          if (file == NULL)
            f->eax = -1;
          else {
            const off_t read = file_read(file, buffer, size);
            f->eax = read;
          }
        }
        break;
      }
      case SYS_WRITE:
      {
        struct thread* current_thread = thread_current();
        int fd = *(int **)(f->esp+4);
        char* buffer = *(char **)(f->esp+8);
        unsigned int size = *(unsigned **)(f->esp+12);

        if(buffer == NULL ||  !validate_buffer(buffer, size) || !validate_userpointers(f->esp+4) || !validate_userpointers(f->esp+12))  // validating if buffer, file descriptor, size is valid
        {
          exit(-1);
          break;
        }

        // returining -1 in case of invalid FD
        if (fd < 0 || fd > 129 || fd == STDIN_FILENO) {
          f->eax = -1;
          break;
        }
        // Writing to console in case of standard output
        if(fd == STDOUT_FILENO)
        {
          for (unsigned int i = 0; i < size; i++) {
              putchar(buffer[i]);
            }
            f->eax = size;
        }
        else
        {
          struct file* file = current_thread->fds[fd - 2];
          if (file == NULL)
            f->eax = -1;
          else {
            off_t written = file_write (file, buffer, size);
            f->eax = written;
          }
        }
    break;
    }
    case SYS_EXIT:
    {
      int status = *(int **)(f->esp+4);
      //printf("\n[SYSCALL] SYS_EXIT - status - %d \n", status);
      if(!validate_userpointers(f->esp+4))  // validating if exit status is valid
      {
        exit(-1);
        break;
      }
      exit(status);
      break;
    }
    case SYS_EXEC:
    {
      char* file_name = *(char **)(f->esp+4);
      //printf("\n[SYSCALL] SYS_EXEC - filename - %s \n", file_name);
      if(!validate_string(file_name) || file_name == NULL) // validating if filename is valid
      {
        exit(-1);
        break;
      }
      tid_t p_id = process_execute(file_name);
      f->eax = p_id;
      break;
    }
    case SYS_WAIT:
    {
      //printf("\n [SYSCALL] Process Wait Called\n");
      tid_t *p_id = (tid_t**)(f->esp+4);
      if(!validate_userpointers(f->esp+4))  // validating if p is valid
      {
        exit(-1);
        break;
      }
      f->eax = process_wait(*p_id);
      break;
    }
    case SYS_SEEK:
    {
      struct thread* current_thread = thread_current();
      int fd = *(int **)(f->esp+4);
      unsigned position = *(unsigned **)(f->esp+8);

      if(!validate_userpointers(f->esp+4) || !validate_userpointers(f->esp+8))
      {
        exit(-1);
        break;
      }

      if (fd < 0 || fd > 129 || fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        f->eax = -1;
        break;
      }
      else
      {
        struct file* file = current_thread->fds[fd - 2];
        if (file == NULL)
          f->eax = -1;
        else {
          file_seek(file, position);
        }
      }
      break;
    }
    case SYS_TELL:
    {
      struct thread* current_thread = thread_current();
      int fd = *(int **)(f->esp+4);

      if(!validate_userpointers(f->esp+4))
      {
        exit(-1);
        break;
      }

      if (fd < 0 || fd > 129 || fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        f->eax = -1;
        break;
      }
      else
      {
        struct file* file = current_thread->fds[fd - 2];
        if (file == NULL)
          f->eax = -1;
        else {
          f->eax = file_tell(file);
        }
      }
      break;
    }
    case SYS_FILESIZE:
    {
      struct thread* current_thread = thread_current();
      int fd = *(int **)(f->esp+4);

      if(!validate_userpointers(f->esp+4))
      {
        exit(-1);
        break;
      }

      if (fd < 0 || fd > 129 || fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        f->eax = -1;
        break;
      }
      else
      {
        struct file* file = current_thread->fds[fd - 2];
        if (file == NULL)
          f->eax = -1;
        else {
          f->eax = file_length(file);
        }
      }
      break;
    }
    case SYS_REMOVE:
    {
      const char *name = *((char**)(f->esp+4));

      if(!validate_userpointers(name) || name == NULL)
      {
        exit(-1);
        break;
      }

      int sucess = filesys_remove(name);
      //printf("\n [SYSCALL] SYS_REMOVE sucess - %d\n",sucess);
      f->eax = sucess;
      break;
    }
    default:
    {
      printf("system call - Not Implemented !!!\n");
    }
  }
}
