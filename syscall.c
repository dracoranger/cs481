#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include <kernel/hash.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"


static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *upath, char *const uargv[]);
static int sys_wait (tid_t);
static int sys_creat (const char *upath, unsigned initial_size);
static int sys_unlink (const char *upath);
static int sys_open (const char *upath);
static int sys_filesize (int fd);
static int sys_read (int fd, void *udst_, unsigned size);
static int sys_write (int fd, void *usrc_, unsigned size);
static int sys_seek (int fd, unsigned position);
static int sys_tell (int fd);
static int sys_close (int fd);
static int sys_semcreat (const char *name, int initial_value);
static int sys_semdestroy (const char *name);
static int sys_semwait (const char *name);
static int sys_semsignal (const char *name);

static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
/* Serializes file system operations. */
static struct lock fs_lock;

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
  /* TODO (Phase 3): Initialize necessary objects. */
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);
}
/* A system call. */
struct syscall
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
  /* TODO (Phase 3): Initialize necessary objects. */
}

/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
  typedef int syscall_function (int, int, int);

  /* A system call. */
  struct syscall
  {
    size_t arg_cnt; /* Number of arguments. */
    syscall_function *func; /* Implementation. */
  };

  /* Table of system calls. */
  static const struct syscall syscall_table[] =
  {
    {0, (syscall_function *) sys_halt},
    {1, (syscall_function *) sys_exit},
    {2, (syscall_function *) sys_exec},
    {1, (syscall_function *) sys_wait},
    {2, (syscall_function *) sys_creat},
    {1, (syscall_function *) sys_unlink},
    {1, (syscall_function *) sys_open},
    {1, (syscall_function *) sys_filesize},
    {3, (syscall_function *) sys_read},
    {3, (syscall_function *) sys_write},
    {2, (syscall_function *) sys_seek},
    {1, (syscall_function *) sys_tell},
    {1, (syscall_function *) sys_close},
    {2, (syscall_function *) sys_semcreat},
    {1, (syscall_function *) sys_semdestroy},
    {1, (syscall_function *) sys_semwait},
    {1, (syscall_function *) sys_semsignal},
  };

  const struct syscall *sc;
  unsigned call_nr;
  int args[3];

  /* Get the system call. */
  copy_in (&call_nr, f->esp, sizeof call_nr);
  if (call_nr >= sizeof syscall_table / sizeof *syscall_table)
  thread_exit ();
  sc = syscall_table + call_nr;

  /* Get the system call arguments. */
  ASSERT (sc->arg_cnt <= sizeof args / sizeof *args);
  memset (args, 0, sizeof args);
  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * sc->arg_cnt);

  /* Execute the system call,
  and set the return value. */
  f->eax = sc->func (args[0], args[1], args[2]);
}

/* Returns true if UADDR is a valid, mapped user address,
false otherwise. */
static bool
verify_user (const void *uaddr)
{
  struct thread *t = thread_current ();

  ASSERT (NULL != t->pcb);

  return (uaddr < PHYS_BASE
    && pagedir_get_page (t->pagedir, uaddr) != NULL);
  }
}
/* Returns true if UADDR--UADDR + SIZE are valid, mapped user addresses,
false otherwise. */
static bool
verify_user_range (const void *uaddr, size_t size)
{
  bool ok= true;
  size_t offset = 0;

  while (true) {
    ok = verify_user (uaddr + offset);
    if (! ok)
    {
      goto done;
    }

    /* More to check because remaining size > page size. */
    if (size >= PGSIZE)
    {
      offset += PGSIZE;
      size -= PGSIZE;
      /* One more check because remaining size < page size but spans page boundary. */
      else if (size > PGSIZE - pg_ofs (uaddr))
      {
        offset += PGSIZE;
        size= 0;
      }
      else
      {
        break;
      }
    }

    done:
    return ok;
  }

  /* Copies a byte from user address USRC to kernel address DST.
  USRC must be below PHYS_BASE.
  Returns true if successful, false if a segfault occurred. */

  static inline bool
  get_user (uint8_t *dst, const uint8_t *usrc)
  {
    int eax;
    asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
    return eax != 0;
  }

  /* Writes BYTE to user address UDST.
  UDST must be below PHYS_BASE.
  Returns true if successful, false if a segfault occurred. */
  static inline bool
  put_user (uint8_t *udst, uint8_t byte)
  {
    int eax;
    asm ("movl $1f, %%eax; movb %b2, %0; 1:"
    : "=m" (*udst), "=&a" (eax) : "q" (byte));
    return eax != 0;
  }
  /* Copies SIZE bytes from user address USRC to kernel address
  DST.
  Call thread_exit() if any of the user accesses are invalid. */
  static void
  copy_in (void *dst_, const void *usrc_, size_t size)
  {
    uint8_t *dst = dst_;
    const uint8_t *usrc = usrc_;

    for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
    thread_exit ();
  }

  /* Creates a copy of user string US in kernel memory
  and returns it as a page that must be freed with
  palloc_free_page().
  Truncates the string at PGSIZE bytes in size.
  Call thread_exit() if any of the user accesses are invalid. */
  static char *
  copy_in_string (const char *us)
  {
    char *ks;
    size_t length;

    ks = palloc_get_page (0);
    if (ks == NULL)
    thread_exit ();

    for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user ((uint8_t *) ks + length, (uint8_t *) us++))
      {
        palloc_free_page (ks);
        thread_exit ();
        if (ks[length] == '\0')
        return ks;
      }
      ks[PGSIZE - 1] = '\0';
      return ks;
    }
  }
  /* Creates a copy of argv-style user string array UARGV in kernel memory
  and returns it as a page that must be freed with
  palloc_free_page().
  Call thread_exit() if |argv| > PGSIZE.
  Call thread_exit() if any of the user accesses are invalid. */
  static char **
  copy_in_argv (char *const uargv[])
  {
    char **kargv;
    char *ptr;
    size_t count= 0;
    size_t length = 0;

    kargv = palloc_get_page (0);
    if (kargv == NULL)
    /* First get number of pointers in argv. */
    for (count = 0; uargv[count]; count++) {}

    /* Beginning of empty space after pointer array and NULL. */
    ptr = (char *) (kargv + count + 1);

    /* For each pointer in argv ... */
    for (int i = 0; i < count; i++)
    {
      /* ... copy string beyond end of pointer array. */
      for (length = 0; length < PGSIZE; length++)
      {
        if (uargv >= (char **) PHYS_BASE || !get_user ((uint8_t *) ptr + length, (uint8_t *$
          {
            thread_exit ();
          }

          if (ptr[length] == '\0')
          {
            break;
          }
        }

        if (ptr[length] != '\0')
        {
          thread_exit ();
        }
        char **v = kargv + i;
        memcpy (v, &ptr, sizeof (ptr));

        ptr += length + 1;
      }

      kargv[count] = 0x00;

      return kargv;
    }
  }
  /* Halt system call. */
  static int
  sys_halt (void)
  {
    shutdown_power_off ();
  }

  /* Exit system call. */
  static int
  sys_exit (int status)
  {
    /* TODO (Phase 2): Implement exit system call. */
    struct thread *cur = thread_current();

    ASSERT(NULL != cur);//pcb should never be null
    cur-> pcb-> exit_code = status;
    int hasChildren = 1;
    int currentChild = 1;
    while(hasChildren){
      if(child_pid[currentChild]!=NULL){
          child_pid[currentChild].sys_exit(status);
      }
      else{
          hasChildren=0;
      }
      currentChild=currentChild+1;
    }
    thread_exit();
    /*
    for (int fd = 0; fd < MAX_FILES; fd++)
    {
      close_fd(fd);
    }
    */
    return -1;
  }

  /* Exec system call. */
  static int
  sys_exec (const char *upath, char *const uargv[])
  {
    int ret= -1;
    /* TODO (Phase 2): Implement exec system call. */
    //return -1;
    if(verify_user_range(upath,upath.size())&&verify_user_range(uargv,upath.size()))
    {//probably need to fix fixe
      //lock?

      char *kstr= copy_in_string(*upath);
      char **kargv = copy_in_argv(* uargv[])

      lock_acquire (&fs_lock);
      ret= process_execute(kstr, kargv);
      lock_release (&fs_lock);

      palloc_free_page (kargv);
      palloc_free_page (kstr);
    }
    return ret;
  }

  /* Wait system call. */
  static int
  sys_wait (int child)
  {
    /* TODO (Phase 2): Implement wait system call. */

    int ret = -1;
    struct thread *cur = thread_current();

    ASSERT(NULL != cur);

    int chi = cur->child_pid[child]; //since it must be a child, both parent and child cannot wait on each other, i think

    lock_acquire (&fs_lock);
    ret=process_wait(chi);
    lock_release (&fs_lock);

    return ret;

  }

  /* Create system call. */
  static int
  sys_creat (const char *upath, unsigned initial_size)
  {
    char *kpath = copy_in_string (upath);
    bool ok;

    lock_acquire (&fs_lock);
    ok = filesys_create (kpath, initial_size);
    lock_release (&fs_lock);

    palloc_free_page (kpath);

    return ok;
  }

  /* Unlink system call. */
  static int
  sys_unlink (const char *upath)
  {
    char *kpath = copy_in_string (upath);
    bool ok;

    lock_acquire (&fs_lock);
    ok = filesys_remove (kpath);
    lock_release (&fs_lock);

    palloc_free_page (kpath);

    return ok;
  }

  /* Returns the next unused file descriptor or -1 if fds is full. */
  static int
  next_fd (void)
  {
    int fd = MAX_FILES;

    struct thread *cur = thread_current ();

    ASSERT (NULL != cur->pcb);

    /* Skip 0 and 1 which represent stdin and stdout. */
    for (fd = STDOUT_FILENO + 1; fd < MAX_FILES; fd++)
    {
      if (NULL == cur->pcb->fds[fd])
      {
        break;
      }
    }

    return fd < MAX_FILES ? fd : -1;
  }

  /* Return file * corresponding to fd or NULL if fd is invalid. */
  static struct file *
  lookup_fd (int fd)
  {
    struct file *f = NULL;

    struct thread *cur = thread_current ();

    ASSERT (NULL != cur->pcb);

    if (fd < 0 || fd >= MAX_FILES)
    {
      goto done;
    }

    f = cur->pcb->fds[fd];

    done:
    return f;
  }

  static void
  close_fd (int fd)
  {
    struct thread *cur = thread_current ();

    ASSERT (NULL != cur->pcb);

    struct file *f = cur->pcb->fds[fd];
    if (NULL == f)
    {
      goto done;
    }

    lock_acquire (&fs_lock);
    file_close (f);
    lock_release (&fs_lock);

    cur->pcb->fds[fd] = NULL;

    done:
    return;
  }

  /* Open system call. */
  static int
  sys_open (const char *upath)
  {
    char *kpath = copy_in_string (upath);

    int fd = next_fd();
    if (-1 == fd)
    {
      goto done;
    }

    lock_acquire (&fs_lock);

    struct thread *cur = thread_current ();

    ASSERT (NULL != cur->pcb);

    cur->pcb->fds[fd] = filesys_open (kpath);
    if (NULL == cur->pcb->fds[fd])
    {
      fd = -1;
    }

    lock_release (&fs_lock);

    palloc_free_page (kpath);

    done:
    return fd;
  }

  /* Filesize system call. */
  static int
  sys_filesize (int fd)
  {
    int size = -1;

    struct file *f = lookup_fd(fd);
    if (NULL == f)
    {
      goto done;
    }

    lock_acquire (&fs_lock);
    size = file_length (f);
    lock_release (&fs_lock);

    done:
    return size;
  }

  /* Read system call. */
  static int
  sys_read (int fd, void *udst_, unsigned size)
  {
    uint8_t *udst = udst_;
    int bytes_read = -1;

    /* We might want to wait until we actually try to store into an unmapped
    * page before terminating the process (i.e., read into one page at a time).
    * It is possible that the process would have gotten lucky and encountered
    * a short read. But the code here is simpler for students to reason about,
    * and we have not yet covered the details of paging in class.
    */
    if (! verify_user_range (udst, size))
    {
      thread_exit ();
    }

    /* Handle keyboard reads. */
    if (fd == STDIN_FILENO)
    {
      for (bytes_read = 0; (size_t) bytes_read < size; bytes_read++)
      {
        *udst++ = input_getc ();
      }
    }
    else
    {
      /* Handle all other reads. */
      struct file *f = lookup_fd (fd);
      if (NULL == f)
      {
        goto done;
      }

      lock_acquire (&fs_lock);

      /* Read from file into memory. */
      bytes_read = file_read (f, udst, size);

      lock_release (&fs_lock);
    }

    done:
    return bytes_read;
  }

  /* Write system call. */
  static int
  sys_write (int fd, void *usrc_, unsigned size)
  {
    uint8_t *usrc = usrc_;
    int bytes_written = -1;
    struct file *f = NULL;

    /* We might want to wait until we actually try to load from an unmapped
    * page before terminating the process (i.e., write one page at a time).
    * It is possible that the process would have gotten lucky and encountered
    * a short write. But the code here is simpler for students to reason about,
    * and we have not yet covered the details of paging in class.
    */
    if (! verify_user_range (usrc, size))
    {
      thread_exit ();
    }

    /* Do the write. */
    if (fd == STDOUT_FILENO)
    {
      putbuf (usrc, size);
      bytes_written = size;
    }
    else
    {
      f = lookup_fd (fd);
      if (NULL == f)
      {
        goto done;
      }

      lock_acquire (&fs_lock);
      bytes_written = file_write (f, usrc, size);
      lock_release (&fs_lock);
    }

    done:
    return bytes_written;
  }

  /* Seek system call. */
  static int
  sys_seek (int fd, unsigned position)
  {
    int fnval = -1;

    struct file *f = lookup_fd (fd);
    if (NULL == f)
    {
      goto done;
    }

    lock_acquire (&fs_lock);
    if ((off_t) position >= 0)
    {
      file_seek (f, position);
    }
    lock_release (&fs_lock);

    fnval = 0;

    done:
    return fnval;
  }

  /* Tell system call. */
  static int
  sys_tell (int fd)
  {
    int position = -1;

    struct file *f = lookup_fd (fd);
    if (NULL == f)
    {
      goto done;
    }

    lock_acquire (&fs_lock);
    position = file_tell (f);
    lock_release (&fs_lock);

    done:
    return position;
  }

  /* Close system call. */
  static int
  sys_close (int fd)
  {
    int fnval = -1;

    struct file *f = lookup_fd (fd);
    if (NULL == f)
    {
      goto done;
    }

    close_fd(fd);

    done:
    return fnval;
  }

  /* On thread exit, close all open files. */
  void
  syscall_exit (void)
  {
    for (int fd = 0; fd < MAX_FILES; fd++)
    {
      close_fd(fd);
    }
  }

  /* System call which creates a semaphore. */
  static int
  sys_semcreat (const char *uname, int initial_value)
  {
    /* TODO (Phase 3): Implement semcreate system call. */
    return -1;
  }

  /* System call which destroys a semaphore. */
  static int
  sys_semdestroy (const char *uname)
  {
    /* TODO (Phase 3): Implement semdestroy system call. */
    return -1;
  }

  /* System call which waits on a semaphore. */
  static int
  sys_semwait (const char *uname)
  {
    /* TODO (Phase 3): Implement semwait system call. */
    return -1;
  }

  /* System call which signals a semaphore. */
  static int
  sys_semsignal (const char *uname)
  {
    /* TODO (Phase 3): Implement semsignal system call. */
    return -1;
  }

  //Process.h
#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Maximum number of open files per thread. */
#define MAX_FILES 128
#define MAX_CHILD 128

typedef int pid_t;
#define PID_ERROR ((pid_t) -1)          /* Error value for pid_t. */

/* TODO (Phase 2): Remove these and replace them a data structures/variables
   within struct process which maintain a number of children
   and track exit code. */
static struct pcb *pcb;
static int exit_code = -1;



struct pcb
  {



    struct thread *thread;              /* Kernel thread associated with process. */
    pid_t pid;                          /* The process ID. */
    struct semaphore dead;              /* 1=I am alive, 0=I am dead. */
    struct file *bin_file;              /* Executable. */
    struct file *fds[MAX_FILES];        /* Array of open file descriptors. */
    /* TODO (Phase 2): Add children data structure (see also above). */
    int *child_pid[MAX_CHILD];
    /* TODO (Phase 2): Add tracking of exit code(s) (see also above). */
    int exit_code;
  };

void process_init (void);
void init_process (struct pcb *pcb, struct thread *thread);
pid_t process_execute (const char *path, char **argv);
int process_wait (pid_t);
void process_exit (void);
void process_notify_parent (void);
void process_activate (void);

#endif /* userprog/process.h */

//process.c

#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static thread_func start_process NO_RETURN;
static bool load (const char *path, char **argv, void (**eip) (void), void **esp);

/* Data structure shared between process_execute() in the
   invoking thread and start_process() in the newly invoked
   thread. */
struct exec_info
  {
    const char *path;                   /* Program to load. */
    char **argv;                        /* Program arguments. */
    struct semaphore load_done;         /* "Up"ed when loading complete. */
    struct thread *thread;              /* Child process. */
    bool success;                       /* Program successfully loaded? */
  };

/* TODO (Phase 2): Track available PIDs. */
static struct lock pid_lock;

//int current_pid=0;

void
process_init (void)
{
  lock_init (&pid_lock);
}

/* Returns a pid to use for a new process. */
static pid_t
allocate_pid (void)
{
  /* TODO (Phase 2): Return next unused PID. Do not forget to lock. */
  int ret= -1;
//check lock
//aquire lock
//set ret value
//incriment
//unlock

return ret

  //return -1;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or PID_ERROR if the thread cannot be created. */
pid_t
process_execute (const char *path, char **argv)
{
  struct exec_info exec;
  char thread_name[16];
  tid_t tid = TID_ERROR;
  pid_t pid = PID_ERROR;
  struct thread *cur = thread_current ();

  ASSERT (NULL != cur->pcb);

  /* Initialize exec_info. */
  exec.path = path;
  exec.argv = argv;
  sema_init (&exec.load_done, 0);

  /* Create a new thread to execute FILE_NAME. */
  strlcpy (thread_name, path, sizeof thread_name);
  tid = thread_create (thread_name, PRI_DEFAULT, start_process, &exec);
  if (tid == TID_ERROR)
    {
      pid = PID_ERROR;
      goto done;
    }

  sema_wait (&exec.load_done);
  if (exec.success)
    {
      ASSERT (NULL != exec.thread);
      ASSERT (NULL != exec.thread->pcb);

      /* Obtain a PID. */
      pid = exec.thread->pcb->pid = allocate_pid ();

      /* TODO (Phase 2): Replace: add exec.thread->pcb to children data structure. */
      ASSERT (NULL == pcb);
      pcb = exec.thread->pcb;
    }
  else
    {
      pid = PID_ERROR;
    }

done:
  return pid;
}

/* Allocate and initialize a PCB. */
void
init_process (struct pcb *pcb, struct thread *thread)
{
  ASSERT (NULL != pcb);

  /* TODO (Phase 2): Initialize any fields you added to struct process. */
  //pcb->child_pid[next] = //Not sure if we need to intialize anything at the moment

  pcb->thread = thread;

  sema_init (&pcb->dead, 0);
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *exec_)
{
  struct thread *cur = thread_current ();
  struct exec_info *exec = exec_;
  struct intr_frame if_;
  bool success = false;

  /* Allocate a PCB. */
  ASSERT (NULL == cur->pcb);
  cur->pcb = palloc_get_page (PAL_ZERO);
  if (NULL == cur->pcb)
    {
      goto done;
    }

  init_process (cur->pcb, cur);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (exec->path, exec->argv, &if_.eip, &if_.esp);

done:
  /* Provide parent with pointer to this thread. */
  exec->thread = cur;

  /* Notify parent thread and clean up. */
  exec->success = success;
  sema_signal (&exec->load_done);

  if (!success)
    {
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Ensure thread no longer in thread.c's all_list. */
static void
panic_if_threads_same (struct thread *t, struct thread *zombie)
{
  if (&t->allelem == &zombie->allelem)
    {
      PANIC ("About to destroy kernel thread that we might later schedule");
    }
}

/* Ensure thread no longer in thread.c's all_list. */
static bool
thread_cannot_schedule (struct thread *zombie)
{
  /* Bad performance, but should only be called from ASSERT (). */
  enum intr_level old_level = intr_disable ();
  thread_foreach ((thread_action_func *) panic_if_threads_same, &zombie->allelem);
  intr_set_level (old_level);

  return true;
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (pid_t child_pid)
{
  int exit_code = -1;
  struct thread *cur = thread_current ();

  ASSERT (NULL != cur->pcb);

  /* TODO (Phase 2): Replace: lookup in children data structure by child_pid. */
  struct pcb *child = pcb;
  if (NULL == child)
    {
      goto done;
    }
  ASSERT (NULL != child->thread);

  sema_wait (&child->dead);
  /* TODO (Phase 2): Get child's exit code. */
  exit_code=child->exit_code;//added think it works
  ASSERT (thread_cannot_schedule (child->thread)); /* A little healthy paranoia:
                                                      we do not want to free a thread
                                                      that could later run. Otherwise,
                                                      thread_schedule_tail might free it
                                                      again. */

  /* Finally free zombie. */

  /* TODO (Phase 2): Remove from children data structure. */
  palloc_free_page(cur->pcb->child_pid);//Added think its something like this
  palloc_free_page (child->thread);
  palloc_free_page (child);

done:
  return exit_code;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  ASSERT (NULL != cur->pcb);

  /* Close executable (and allow writes). */
  file_close (cur->pcb->bin_file);

  /* TODO (Phase 2): Free entries in children data structure. */

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Notify parent that we are dead. */
void
process_notify_parent (void)
{
  struct thread *cur = thread_current ();

  ASSERT (NULL != cur->pcb);

  /* TODO (Phase 2): Replace global exit_code with the use of
     your exit code field/variable. */
  printf ("%s: exit(%d)\n", cur->name, cur->exit_code);//added cur->exit_code
  sema_signal (&cur->pcb->dead);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (char **argv, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *_path, char **argv, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  char path[NAME_MAX + 2];
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  char *cp;
  int i;

  ASSERT (NULL != t->pcb);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Fix up path. */
  while (*_path == ' ')
    _path++;
  strlcpy (path, _path, sizeof path);
  cp = strchr (path, ' ');
  if (cp != NULL)
    *cp = '\0';

  /* Open executable file. */
  t->pcb->bin_file = file = filesys_open (path);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", path);
      goto done;
    }
  file_deny_write (file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", path);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (argv, esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Reverse the order of the ARGC pointers to char in ARGV. */
static void
reverse (int argc, char **argv)
{
  for (; argc > 1; argc -= 2, argv++)
    {
      char *tmp = argv[0];
      argv[0] = argv[argc - 1];
      argv[argc - 1] = tmp;
    }
}

/* Pushes the SIZE bytes in BUF onto the stack in KPAGE, whose
   page-relative stack pointer is *OFS, and then adjusts *OFS
   appropriately.  The bytes pushed are rounded to a 32-bit
   boundary.

   If successful, returns a pointer to the newly pushed object.
   On failure, returns a null pointer. */
static void *
push (uint8_t *kpage, size_t *ofs, const void *buf, size_t size)
{
  size_t padsize = ROUND_UP (size, sizeof (uint32_t));
  if (*ofs < padsize)
    return NULL;

  *ofs -= padsize;
  memcpy (kpage + *ofs + (padsize - size), buf, size);
  return kpage + *ofs + (padsize - size);
}

/* Sets up command line arguments in KPAGE, which will be mapped
   to UPAGE in user space.  The command line arguments are taken
   from CMD_LINE, separated by spaces.  Sets *ESP to the initial
   stack pointer for the process. */
static bool
init_cmd_line (uint8_t *kpage, uint8_t *upage, char **_argv, void **esp)
{
  size_t ofs = PGSIZE;
  char *const null = NULL;
  int argc;
  char **orig_argv, **argv;

  /* Push command line strings. */
  for (argc = 0; _argv[argc]; argc++) {}
  orig_argv = argv = palloc_get_page (0);
  if (NULL == argv)
    {
      PANIC("BOO!");
    }

  for (int i = 0; i < argc; i++)
    {
      /* Replace each pointer in argv with the new user-space pointer. */
      argv[i] = push (kpage, &ofs, _argv[i], strlen (_argv[i]) + 1);
      if (argv[i] == NULL)
        {
          return false;
        }
    }

  if (push (kpage, &ofs, &null, sizeof null) == NULL)
    {
      return false;
    }

  /* Parse command line into arguments and push them in reverse order. */
  for (int i = 0; i < argc; i++)
    {
      char *arg;
      arg = argv[i];
      void *uarg = upage + (arg - (char *) kpage);
      if (push (kpage, &ofs, &uarg, sizeof uarg) == NULL)
        {
          return false;
        }
    }

  /* Reverse the order of the command line arguments. */
  argv = (char **) (upage + ofs);
  reverse (argc, (char **) (kpage + ofs));

  /* Push argv, argc, "return address". */
  if (push (kpage, &ofs, &argv, sizeof argv) == NULL
      || push (kpage, &ofs, &argc, sizeof argc) == NULL
      || push (kpage, &ofs, &null, sizeof null) == NULL)
    return false;

  palloc_free_page (orig_argv);

  /* Set initial stack pointer. */
  *esp = upage + ofs;
  return true;
}

/* Create a minimal stack for T by mapping a page at the
   top of user virtual memory.  Fills in the page using CMD_LINE
   and sets *ESP to the stack pointer. */
static bool
setup_stack (char **argv, void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      uint8_t *upage = ((uint8_t *) PHYS_BASE) - PGSIZE;
      if (install_page (upage, kpage, true))
        success = init_cmd_line (kpage, upage, argv, esp);
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  ASSERT (NULL != t->pcb);

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
