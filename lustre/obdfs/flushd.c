/*
 * OBDFS Super operations - also used for Lustre file system
 *
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 * Copryright (C) 1999 Stelias Computing Inc. <braam@stelias.com>
 * Copryright (C) 1999 Seagate Technology Inc.
 *
 */
#define __NO_VERSION__
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/malloc.h>
#include <linux/locks.h>
#include <linux/errno.h>
#include <linux/swap.h>
#include <linux/smp_lock.h>
#include <linux/vmalloc.h>
#include <linux/blkdev.h>
#include <linux/sysrq.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/quotaops.h>
#include <linux/iobuf.h>
#include <linux/highmem.h>

#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bitops.h>
#include <asm/mmu_context.h>

#include <linux/obd_support.h>
#include <linux/obd_class.h>
#include <linux/obdfs.h>


struct {
	int nfract;  /* Percentage of buffer cache dirty to 
			activate bdflush */
	int ndirty;  /* Maximum number of dirty blocks to write out per
			wake-cycle */
	int nrefill; /* Number of clean buffers to try to obtain
				each time we call refill */
	int nref_dirt; /* Dirty buffer threshold for activating bdflush
			  when trying to refill buffers. */
	int interval; /* jiffies delay between pupdate flushes */
	int age_buffer;  /* Time for normal buffer to age before we flush it */
	int age_super;  /* Time for superblock to age before we flush it */
} pupd_prm = {40, 500, 64, 256, 5*HZ, 30*HZ, 5*HZ };

/* Called with the superblock list lock */
static int obdfs_enqueue_pages(struct inode *inode, struct obdo **obdo,
			       int nr_slots, struct page **pages, char **bufs,
			       obd_size *counts, obd_off *offsets,
			       obd_flag *flag, unsigned long check_time)
{
	struct list_head *page_list = obdfs_iplist(inode);
	struct list_head *tmp;
	int num = 0;

	ENTRY;

	tmp = page_list;
	/* Traverse list in reverse order, so we do FIFO, not LIFO order */
	while ( (tmp = tmp->prev) != page_list && num < nr_slots ) {
		struct obdfs_pgrq *req;
		struct page *page;
		
		req = list_entry(tmp, struct obdfs_pgrq, rq_plist);
		page = req->rq_page;

		
		if (req->rq_jiffies > check_time)
			break;		/* pages are in chronological order */

		/* Only allocate the obdo if we will actually do I/O here */
		if ( !*obdo ) {
			OIDEBUG(inode);
			*obdo = obdo_fromid(IID(inode), inode->i_ino,
					    OBD_MD_FLNOTOBD);
			if ( IS_ERR(*obdo) ) {
				int err = PTR_ERR(*obdo);
				*obdo = NULL;

				EXIT;
				return err;
			}

			/* FIXME revisit fromid & from_inode */
			obdfs_from_inode(*obdo, inode);
			*flag = OBD_BRW_CREATE;
		}

		/* Remove request from list before write to avoid conflict.
		 * Note that obdfs_pgrq_del() also deletes the request.
		 */
		obdfs_pgrq_del(req);
		if ( !page ) {
			CDEBUG(D_CACHE, "no page \n");
			continue;
		}

		bufs[num] = (char *)page_address(page);
		pages[num] = page;
		counts[num] = PAGE_SIZE;
		offsets[num] = ((obd_off)page->index) << PAGE_SHIFT;
		CDEBUG(D_INFO, "ENQ inode %ld, page %p addr %p to vector\n", 
		       inode->i_ino, page, (char *)page_address(page));
		num++;
	}

	if (!list_empty(page_list))
		CDEBUG(D_INFO, "inode %ld list not empty\n", inode->i_ino);
	CDEBUG(D_INFO, "added %d page(s) to vector\n", num);

	EXIT;
	return num;  
} /* obdfs_enqueue_pages */

/* Remove writeback requests for the superblock */
int obdfs_flush_reqs(struct list_head *inode_list, unsigned long check_time)
{
	struct list_head *tmp;
	int		  total_io = 0;
	obd_count	  num_io;
	obd_count         num_obdos;
	struct inode	 *inodes[MAX_IOVEC];	/* write data back to these */
	struct page	 *pages[MAX_IOVEC];	/* call put_page on these */
	struct obdo	 *obdos[MAX_IOVEC];
	char		 *bufs[MAX_IOVEC];
	obd_size	  counts[MAX_IOVEC];
	obd_off		  offsets[MAX_IOVEC];
	obd_flag	  flags[MAX_IOVEC];
	obd_count         bufs_per_obdo[MAX_IOVEC];
	int		  err = 0;
	struct obdfs_sb_info *sbi;

	ENTRY;
	if (!inode_list) {
		CDEBUG(D_INODE, "no list\n");
		EXIT;
		return 0;
	}

	sbi = list_entry(inode_list, struct obdfs_sb_info, osi_inodes);

	obd_down(&sbi->osi_list_mutex);
	if ( list_empty(inode_list) ) {
		CDEBUG(D_CACHE, "list empty: memory %ld, inodes %d, pages %d\n",
		       obd_memory, obd_inodes, obd_pages);
		obd_up(&sbi->osi_list_mutex);
		EXIT;
		return 0;
	}

	/* Add each inode's dirty pages to a write vector, and write it.
	 * Traverse list in reverse order, so we do FIFO, not LIFO order
	 */
 again:
	tmp = inode_list;
	num_io = 0;
	num_obdos = 0;
	while ( (tmp = tmp->prev) != inode_list && total_io < pupd_prm.ndirty) {
		struct obdfs_inode_info *ii;
		struct inode *inode;
		int res;

		ii = list_entry(tmp, struct obdfs_inode_info, oi_inodes);
		inode = list_entry(ii, struct inode, u);
		inodes[num_obdos] = inode;
		obdos[num_obdos] = NULL;
		CDEBUG(D_INFO, "checking inode %ld pages\n", inode->i_ino);

		/* Make sure we reference "inode" and not "inodes[num_obdos]",
		 * as num_obdos will change after the loop is run.
		 */
		if (!list_empty(obdfs_iplist(inode))) {
			res = obdfs_enqueue_pages(inode, &obdos[num_obdos],
						  MAX_IOVEC - num_io,
						  &pages[num_io], &bufs[num_io],
						  &counts[num_io],
						  &offsets[num_io],
						  &flags[num_obdos],
						  check_time);
			CDEBUG(D_INFO, "FLUSH inode %ld, pages flushed: %d\n",
			       inode->i_ino, res);
			if ( res < 0 ) {
				CDEBUG(D_INODE,
				       "fatal: unable to enqueue inode %ld (err %d)\n",
				       inode->i_ino, err);
				/* XXX Move bad inode to end of list so we can
				 * continue with flushing list.  This is a
				 * temporary measure to avoid machine lockups.
				 */
				list_del(tmp);
				list_add(tmp, inode_list);
				err = res;
				EXIT;
				goto BREAK;
			} else if (res) {
				num_io += res;
				total_io += res;
				bufs_per_obdo[num_obdos] = res;
				num_obdos++;
			}

			if ( num_io == MAX_IOVEC ) {
				obd_up(&sbi->osi_list_mutex);
				err = obdfs_do_vec_wr(inodes, num_io, num_obdos,
						      obdos, bufs_per_obdo,
						      pages, bufs, counts,
						      offsets, flags);
				if ( err ) {
					CDEBUG(D_INODE,
						"fatal: unable to do vec_wr (err %d)\n", err);
					EXIT;
					goto ERR;
				}
				obd_down(&sbi->osi_list_mutex);
				goto again;
			}
		}
	}

BREAK:
	obd_up(&sbi->osi_list_mutex);

	/* flush any remaining I/Os */
	if ( num_io ) {
		err = obdfs_do_vec_wr(inodes, num_io, num_obdos, obdos,
				      bufs_per_obdo, pages, bufs, counts,
				      offsets, flags);
		if (err)
			CDEBUG(D_INODE, "fatal: unable to do vec_wr (err %d)\n", err);
		num_io = 0;
		num_obdos = 0;
	}

	/* Remove inode from superblock dirty list when no more pages.
	 * Make sure we don't point at the current inode with tmp
	 * when we re-init the list on the inode, or we will loop.
	 */
	obd_down(&sbi->osi_list_mutex);
	tmp = inode_list;
	while ( (tmp = tmp->prev) != inode_list ) {
		struct obdfs_inode_info *ii;
		struct inode *inode;

		ii = list_entry(tmp, struct obdfs_inode_info, oi_inodes);
		inode = list_entry(ii, struct inode, u);
		CDEBUG(D_INFO, "checking inode %ld empty\n", inode->i_ino);
		if (list_empty(obdfs_iplist(inode))) {
			CDEBUG(D_INFO, "remove inode %ld from dirty list\n",
			       inode->i_ino);
			tmp = tmp->next;
			list_del(obdfs_islist(inode));
			/* decrement inode reference for page cache */
			inode->i_count--;
			INIT_LIST_HEAD(obdfs_islist(inode));
		}
	}
	obd_up(&sbi->osi_list_mutex);

	CDEBUG(D_INFO, "flushed %d pages in total\n", total_io);
	EXIT;
ERR:
	return err ? err : total_io;
} /* obdfs_flush_reqs */


/* Walk all of the superblocks and write out blocks which are too old.
 * Return the maximum number of blocks written for a single filesystem.
 */
int obdfs_flush_dirty_pages(unsigned long check_time)
{
	struct list_head *sl;
	int max = 0;

	ENTRY;
	sl = &obdfs_super_list;
	while ( (sl = sl->prev) != &obdfs_super_list ) {
		struct obdfs_sb_info *sbi = 
			list_entry(sl, struct obdfs_sb_info, osi_list);
		int ret;

		/* walk write requests here, use the sb, check the time */
		ret = obdfs_flush_reqs(&sbi->osi_inodes, check_time);
		/* XXX handle error?  What to do with it? */

		max = ret > max ? ret : max;
	}
	EXIT;
	return max;
} /* obdfs_flush_dirty_pages */


static struct task_struct *pupdated;

static int pupdate(void *unused) 
{
	int interval = pupd_prm.interval;
	long age = pupd_prm.age_buffer;
	int wrote = 0;
	
	exit_files(current);
	exit_mm(current);

	pupdated = current;
	pupdated->session = 1;
	pupdated->pgrp = 1;
	strcpy(pupdated->comm, "pupdated");

	printk("pupdated activated...\n");

	spin_lock_irq(&pupdated->sigmask_lock);
	sigfillset(&pupdated->blocked);
	siginitsetinv(&pupdated->blocked, sigmask(SIGTERM));
	recalc_sigpending(pupdated);
	spin_unlock_irq(&pupdated->sigmask_lock);

	for (;;) {
		long dirty_limit;

		/* update interval */
		if (interval) {
			set_task_state(pupdated, TASK_INTERRUPTIBLE);
			schedule_timeout(interval);
		}
		if (signal_pending(pupdated))
		{
			int stopped = 0;
			spin_lock_irq(&pupdated->sigmask_lock);
			if (sigismember(&pupdated->signal, SIGTERM))
			{
				sigdelset(&pupdated->signal, SIGTERM);
				stopped = 1;
			}
			recalc_sigpending(pupdated);
			spin_unlock_irq(&pupdated->sigmask_lock);
			if (stopped) {
				printk("pupdated stopped...\n");
				set_task_state(pupdated, TASK_STOPPED);
				pupdated = NULL;
				return 0;
			}
		}
		/* asynchronous setattr etc for the future ...
		obdfs_flush_dirty_inodes(jiffies - pupd_prm.age_super);
		 */
		dirty_limit = nr_free_buffer_pages() * pupd_prm.nfract / 100;
		CDEBUG(D_CACHE, "dirty_limit %ld, cache_count %ld\n",
		       dirty_limit, obdfs_cache_count);

		if (obdfs_cache_count > dirty_limit) {
			interval = 0;
			if ( wrote < pupd_prm.ndirty )
				age >>= 1;
		} else {
			int isave = interval;
			int asave = age;

			if ( wrote < pupd_prm.ndirty >> 1 )
				interval = pupd_prm.interval;
			else
				interval = isave >> 1;

			if (obdfs_cache_count > dirty_limit / 3) {
				age = asave >> 1;
				interval = isave >> 1;
			} else
				age = pupd_prm.age_buffer;
		}

		CDEBUG(D_CACHE, "age %ld, interval %d\n", age, interval);
		wrote = obdfs_flush_dirty_pages(jiffies - age);
	}

}


int obdfs_flushd_init(void)
{
	/*
	kernel_thread(bdflush, NULL, CLONE_FS | CLONE_FILES | CLONE_SIGHAND);
	 */
	kernel_thread(pupdate, NULL, 0);
	CDEBUG(D_PSDEV, __FUNCTION__ ": flushd inited\n");
	return 0;
}

int obdfs_flushd_cleanup(void)
{
	ENTRY;

	if (pupdated) /* for debugging purposes only */
		CDEBUG(D_CACHE, "pupdated->state = %lx\n", pupdated->state);

	/* deliver a signal to pupdated to shut it down */
	if (pupdated && (pupdated->state == TASK_RUNNING ||
			 pupdated->state == TASK_INTERRUPTIBLE )) {
		unsigned long timeout = HZ/20;
		unsigned long count = 0;
		send_sig_info(SIGTERM, (struct siginfo *)1, pupdated);
		while (pupdated) {
			if ((count % 2*HZ) == timeout)
				printk(KERN_INFO "wait for pupdated to stop\n");
			count += timeout;
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(timeout);
		}
	}

	EXIT;
	/* not reached */
	return 0;

}
