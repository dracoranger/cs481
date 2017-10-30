#include "vm/swap.h"
#include <bitmap.h>
#include <debug.h>
#include <stdio.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

/* The swap device. */
static struct block *swap_device;

/* Used swap frames. */
/* TODO (Phase 4): Implement data structure to track which frames
 * in swap space are in use. */

/* Protects data structure above. */
static struct lock swap_lock;

/* Number of sectors per page. */
#define PAGE_SECTORS (PGSIZE / BLOCK_SECTOR_SIZE)

/* Sets up swap. */
void
swap_init (void)
{
  swap_device = block_get_role (BLOCK_SWAP);
  if (swap_device == NULL)
    {
      printf ("no swap device--swap disabled\n");
    }
  else
    {
      /* TODO (Phase 4): Initialize swap-tracking data structure. */
      //hashtable Page 49 (objective) on the pintos manual
    }
  lock_init (&swap_lock);
}

/* Swaps in page P, which must have a locked frame
   (and be swapped out). */
void
swap_in (struct page *p)
{
  ASSERT (p->frame != NULL);
  ASSERT (lock_held_by_current_thread (&p->frame->lock));
  ASSERT (p->sector != (block_sector_t) -1);

  /* TODO (Phase 4): Read enough blocks to load page. */
    for(int i=0; i<PAGE_SECTORS; i++){
      //block read
      block_read(BLOCK_SWAP, p->sector, )

    }
  /* TODO (Phase 4): Mark swap frame as in use in tracking data structure. */

  p->sector = (block_sector_t) -1;
}

/* Swaps out page P, which must have a locked frame. */
bool
swap_out (struct page *p)
{
  size_t slot;

  ASSERT (p->frame != NULL);
  ASSERT (lock_held_by_current_thread (&p->frame->lock));

  lock_acquire (&swap_lock);
  slot = 0;
  /* TODO (Phase 4): Assign a free swap frame to slot (instead of 0), and
   * mark that frame used in tracking data structure. */
  lock_release (&swap_lock);
  if (slot == BITMAP_ERROR)
    return false;

  p->sector = slot * PAGE_SECTORS;
  /* TODO (Phase 4): Write page across blocks on disk. */
  block_write()


  p->private = false;
  p->file = NULL;
  p->file_offset = 0;
  p->file_bytes = 0;

  return true;
}





//XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


#include "vm/frame.h"
#include <stdio.h>
#include "vm/page.h"
#include "devices/timer.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct frame *frames;
static size_t frame_cnt;

static struct lock scan_lock;
static size_t hand;

/* Initialize the frame manager. */
void
frame_init (void)
{
  void *base;

  lock_init (&scan_lock);

  frames = malloc (sizeof *frames * init_ram_pages);
  if (frames == NULL)
    PANIC ("out of memory allocating page frames");

  while ((base = palloc_get_page (PAL_USER)) != NULL)
    {
      struct frame *f = &frames[frame_cnt++];
      lock_init (&f->lock);
      f->base = base;
      f->page = NULL;
    }
}

/* Is this a good frame to evict? */
static bool pick_me (struct frame *f)
{
  /* TODO (Phase 4): Implement a better page-replacement strategy. */
  //Check if it has been looked at before
  //if it has use, else switch and move on
  //return true;
  //Page recently accessed?

  if(f->seen == true){
    return true;

  }
  else{
    f->seen = true;
    return false;

  }
}

/* Tries to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
static struct frame *
try_frame_alloc_and_lock (struct page *page)
{
  size_t i;

  lock_acquire (&scan_lock);

  /* Find a free frame. */
  for (i = 0; i < frame_cnt; i++)
    {
      struct frame *f = &frames[i];
      if (!lock_try_acquire (&f->lock))
        continue;
      if (f->page == NULL)
        {
          f->page = page;
          lock_release (&scan_lock);
          return f;
        }
      lock_release (&f->lock);
    }

  /* No free frame.  Find a frame to evict. */
  for (i = 0; i < frame_cnt * 2; i++)
    {
      /* Get a frame. */
      struct frame *f = &frames[hand];
      if (++hand >= frame_cnt)
        hand = 0;

      if (!lock_try_acquire (&f->lock))
        continue;

      if (f->page == NULL)
        {
          f->page = page;
          lock_release (&scan_lock);
          return f;
        }

      if (! pick_me (f))
        {
          lock_release (&f->lock);
          continue;
        }

      lock_release (&scan_lock);

      /* Evict this frame. */
      if (!page_out (f->page))
        {
          lock_release (&f->lock);
          return NULL;
        }

      f->page = page;
      return f;
    }

  lock_release (&scan_lock);
  return NULL;
}


/* Tries really hard to allocate and lock a frame for PAGE.
   Returns the frame if successful, false on failure. */
struct frame *
frame_alloc_and_lock (struct page *page)
{
  size_t try;

  for (try = 0; try < 3; try++)
    {
      struct frame *f = try_frame_alloc_and_lock (page);
      if (f != NULL)
        {
          ASSERT (lock_held_by_current_thread (&f->lock));
          return f;
        }
      timer_msleep (1000);
    }

  return NULL;
}

/* Locks P's frame into memory, if it has one.
   Upon return, p->frame will not change until P is unlocked. */
void
frame_lock (struct page *p)
{
  /* A frame can be asynchronously removed, but never inserted. */
  struct frame *f = p->frame;
  if (f != NULL)
    {
      lock_acquire (&f->lock);
      if (f != p->frame)
        {
          lock_release (&f->lock);
          ASSERT (p->frame == NULL);
        }
    }
}

/* Releases frame F for use by another page.
   F must be locked for use by the current process.
   Any data in F is lost. */
void
frame_free (struct frame *f)
{
  ASSERT (lock_held_by_current_thread (&f->lock));

  f->page = NULL;
  lock_release (&f->lock);
}

/* Unlocks frame F, allowing it to be evicted.
   F must be locked for use by the current process. */
void
frame_unlock (struct frame *f)
{
  ASSERT (lock_held_by_current_thread (&f->lock));
  lock_release (&f->lock);
}
