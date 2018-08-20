/*
 * GPL HEADER START
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 only,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License version 2 for more details (a copy is included
 * in the LICENSE file that accompanied this code).
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; If not, see
 * http://www.gnu.org/licenses/gpl-2.0.html
 *
 * GPL HEADER END
 */
/*
 * Copyright (c) 2002, 2010, Oracle and/or its affiliates. All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 2011, 2017, Intel Corporation.
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/rw.c
 *
 * Lustre Lite I/O page cache routines shared by different kernel revs
 */

#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/writeback.h>
#include <asm/uaccess.h>

#include <linux/fs.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
/* current_is_kswapd() */
#include <linux/swap.h>

#define DEBUG_SUBSYSTEM S_LLITE

#include <libcfs/libcfs_ptask.h>
#include <obd_cksum.h>
#include "llite_internal.h"
#include <lustre_compat.h>
#include "fs_cache.h"

#define RAS_CDEBUG(ras) CDEBUG(D_READA,					\
	"lrp %lu nra %lu wz %lu cp %lu csr %lu sf %lu sp %lu sl %lu\n",	\
	ras->ras_last_readpage,						\
	ras->ras_next_readahead,					\
	ras->ras_window_size,						\
	ras->ras_consecutive_pages,					\
	ras->ras_consecutive_stride_requests,				\
	ras->ras_stride_offset,						\
	ras->ras_stride_pages,						\
	ras->ras_stride_length)

/*
 * Check whether the read request is in the stride window.
 * If it is in the stride window, return 1, otherwise return 0.
 */
static int index_in_stride_window(struct ll_readahead_state *ras,
				  unsigned long index)
{
	if (ras->ras_stride_length == 0 ||
	    ras->ras_stride_pages == 0 ||
	    ras->ras_stride_pages == ras->ras_stride_length)
		return 0;

	return  index >= ras->ras_stride_offset &&
		index <  ras->ras_stride_offset + ras->ras_stride_pages;
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ll_ras_reset(struct ll_readahead_state *ras, unsigned long index)
{
	ras->ras_next_readahead = index + 1;
	ras->ras_last_readpage = index;
	ras->ras_consecutive_pages = 0;
	ras->ras_window_size = PTLRPC_MAX_BRW_PAGES;
	RAS_CDEBUG(ras);
}

/* called with the ras_lock held or from places where it doesn't matter */
static void ll_ras_reset_stride(struct ll_readahead_state *ras)
{
	ras->ras_consecutive_stride_requests = 0;
	ras->ras_stride_length = 0;
	ras->ras_stride_pages = 0;
	RAS_CDEBUG(ras);
}

void ll_ras_init(struct ll_readahead_state *ras)
{
	spin_lock_init(&ras->ras_lock);
	ll_ras_reset(ras, 0);
	ll_ras_reset_stride(ras);
}

static void ll_ras_detect_stride(struct ll_readahead_state *ras,
				 unsigned long index)
{
	if (index < ras->ras_last_readpage) {
		/* Reset stride window for forward read */
		ll_ras_reset_stride(ras);
		return;
	}

	ras->ras_consecutive_stride_requests = 0;
	ras->ras_stride_pages  = ras->ras_consecutive_pages;
	ras->ras_stride_length = index - ras->ras_last_readpage;
	ras->ras_stride_offset = index;
	RAS_CDEBUG(ras);
}

void ll_ras_update(struct file *f, unsigned long index, unsigned long nr_pages)
{
	struct ll_file_data *fd = LUSTRE_FPRIVATE(f);
	struct ll_readahead_state *ras = &fd->fd_ras;

	spin_lock(&ras->ras_lock);
	/* need for ll_ras_detect_stride() */
	ras->ras_consecutive_pages = nr_pages;

	/* check whether it is in stride I/O mode */
	if (!index_in_stride_window(ras, index)) {
		if (ras->ras_consecutive_stride_requests == 0) {
detect_stride:
			ll_ras_detect_stride(ras, index);
		} else {
			if (index == ras->ras_stride_offset +
				     ras->ras_stride_pages) {
				ras->ras_stride_pages  += nr_pages;
				ras->ras_stride_length += nr_pages;
				ras->ras_consecutive_stride_requests = 0;
			} else if (index == ras->ras_stride_offset +
					    ras->ras_stride_length) {
				ras->ras_stride_offset = index;
			} else {
				if (ras->ras_consecutive_stride_requests > 1)
					ll_ras_reset_stride(ras);
				goto detect_stride;
			}
		}
	}
	ras->ras_consecutive_stride_requests++;

	ras->ras_last_readpage  = index;
	ras->ras_next_readahead = index + nr_pages;
	RAS_CDEBUG(ras);
	spin_unlock(&ras->ras_lock);
}

int ll_writepage(struct page *vmpage, struct writeback_control *wbc)
{
	struct inode	       *inode = vmpage->mapping->host;
	struct ll_inode_info   *lli   = ll_i2info(inode);
        struct lu_env          *env;
        struct cl_io           *io;
        struct cl_page         *page;
        struct cl_object       *clob;
	bool redirtied = false;
	bool unlocked = false;
        int result;
	__u16 refcheck;
        ENTRY;

        LASSERT(PageLocked(vmpage));
        LASSERT(!PageWriteback(vmpage));

	LASSERT(ll_i2dtexp(inode) != NULL);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env))
		GOTO(out, result = PTR_ERR(env));

        clob  = ll_i2info(inode)->lli_clob;
        LASSERT(clob != NULL);

	io = vvp_env_thread_io(env);
        io->ci_obj = clob;
	io->ci_ignore_layout = 1;
        result = cl_io_init(env, io, CIT_MISC, clob);
        if (result == 0) {
                page = cl_page_find(env, clob, vmpage->index,
                                    vmpage, CPT_CACHEABLE);
		if (!IS_ERR(page)) {
			lu_ref_add(&page->cp_reference, "writepage",
				   current);
			cl_page_assume(env, io, page);
			result = cl_page_flush(env, io, page);
			if (result != 0) {
				/*
				 * Re-dirty page on error so it retries write,
				 * but not in case when IO has actually
				 * occurred and completed with an error.
				 */
				if (!PageError(vmpage)) {
					redirty_page_for_writepage(wbc, vmpage);
					result = 0;
					redirtied = true;
				}
			}
			cl_page_disown(env, io, page);
			unlocked = true;
			lu_ref_del(&page->cp_reference,
				   "writepage", current);
			cl_page_put(env, page);
		} else {
			result = PTR_ERR(page);
		}
        }
        cl_io_fini(env, io);

	if (redirtied && wbc->sync_mode == WB_SYNC_ALL) {
		loff_t offset = cl_offset(clob, vmpage->index);

		/* Flush page failed because the extent is being written out.
		 * Wait for the write of extent to be finished to avoid
		 * breaking kernel which assumes ->writepage should mark
		 * PageWriteback or clean the page. */
		result = cl_sync_file_range(inode, offset,
					    offset + PAGE_SIZE - 1,
					    CL_FSYNC_LOCAL, 1);
		if (result > 0) {
			/* actually we may have written more than one page.
			 * decreasing this page because the caller will count
			 * it. */
			wbc->nr_to_write -= result - 1;
			result = 0;
		}
	}

	cl_env_put(env, &refcheck);
	GOTO(out, result);

out:
	if (result < 0) {
		if (!lli->lli_async_rc)
			lli->lli_async_rc = result;
		SetPageError(vmpage);
		if (!unlocked)
			unlock_page(vmpage);
	}
	return result;
}

int ll_writepages(struct address_space *mapping, struct writeback_control *wbc)
{
	struct inode *inode = mapping->host;
	loff_t start;
	loff_t end;
	enum cl_fsync_mode mode;
	int range_whole = 0;
	int result;
	ENTRY;

	if (wbc->range_cyclic) {
		start = mapping->writeback_index << PAGE_SHIFT;
		end = OBD_OBJECT_EOF;
	} else {
		start = wbc->range_start;
		end = wbc->range_end;
		if (end == LLONG_MAX) {
			end = OBD_OBJECT_EOF;
			range_whole = start == 0;
		}
	}

	mode = CL_FSYNC_NONE;
	if (wbc->sync_mode == WB_SYNC_ALL)
		mode = CL_FSYNC_LOCAL;

	if (ll_i2info(inode)->lli_clob == NULL)
		RETURN(0);

	/* for directio, it would call writepages() to evict cached pages
	 * inside the IO context of write, which will cause deadlock at
	 * layout_conf since it waits for active IOs to complete. */
	result = cl_sync_file_range(inode, start, end, mode, 1);
	if (result > 0) {
		wbc->nr_to_write -= result;
		result = 0;
	}

	if (wbc->range_cyclic || (range_whole && wbc->nr_to_write > 0)) {
		if (end == OBD_OBJECT_EOF)
			mapping->writeback_index = 0;
		else
			mapping->writeback_index = (end >> PAGE_SHIFT) + 1;
	}
	RETURN(result);
}

struct ll_cl_context *ll_cl_find(struct file *file)
{
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_cl_context *lcc;
	struct ll_cl_context *found = NULL;

	read_lock(&fd->fd_lock);
	list_for_each_entry(lcc, &fd->fd_lccs, lcc_list) {
		if (lcc->lcc_cookie == current) {
			found = lcc;
			break;
		}
	}
	read_unlock(&fd->fd_lock);

	return found;
}

void ll_cl_add(struct file *file, const struct lu_env *env, struct cl_io *io)
{
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_cl_context *lcc = &ll_env_info(env)->lti_io_ctx;

	memset(lcc, 0, sizeof(*lcc));
	INIT_LIST_HEAD(&lcc->lcc_list);
	lcc->lcc_cookie = current;
	lcc->lcc_env = env;
	lcc->lcc_io = io;

	write_lock(&fd->fd_lock);
	list_add(&lcc->lcc_list, &fd->fd_lccs);
	write_unlock(&fd->fd_lock);
}

void ll_cl_remove(struct file *file, const struct lu_env *env)
{
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_cl_context *lcc = &ll_env_info(env)->lti_io_ctx;

	write_lock(&fd->fd_lock);
	list_del_init(&lcc->lcc_list);
	write_unlock(&fd->fd_lock);
}

int ll_readpage(struct file *file, struct page *vmpage)
{
	LIST_HEAD(pages);
	struct inode *inode = file_inode(file);
	struct cl_object *clob = ll_i2info(inode)->lli_clob;
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	struct vvp_io *vio;
	struct cl_page *page;
	struct cl_page_list *plist;
	struct cl_page_list local_plist;
	struct address_space *mapping = file->f_mapping;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_readahead_state *ras = &fd->fd_ras;
	size_t nr_pages = 0;
	pgoff_t page_idx = vmpage->index;
	pgoff_t end_idx;
	pgoff_t ra_idx;
	loff_t isize;
	bool pio_enabled = !!(ll_i2sbi(inode)->ll_flags & LL_SBI_PIO);
	int rc = 0;
	ENTRY;

	/*
	rc = lustre_readpage_from_fscache(inode, vmpage);
	if (rc == 0)
		return rc;
	*/

	lcc = ll_cl_find(file);
	if (lcc == NULL || lcc->lcc_io == NULL)
		/* fast read: page cache miss */
		GOTO(out_unlock, rc = -ENODATA);

	env = lcc->lcc_env;
	io  = lcc->lcc_io;

	LASSERT(io->ci_state == CIS_IO_GOING);

	page = cl_page_find(env, clob, page_idx, vmpage, CPT_CACHEABLE);
	if (unlikely(IS_ERR(page)))
		GOTO(out_unlock, rc = PTR_ERR(page));

	LASSERT(page->cp_type == CPT_CACHEABLE);

	if (unlikely(PageUptodate(vmpage)))
		GOTO(out_page_put, rc = 0);

	vio = vvp_env_io(env);
	if (io->ci_type == CIT_READ && vio->vui_io_subtype == IO_NORMAL) {
		plist = &vio->u.read.vui_plist;
		isize = i_size_read(inode);
	} else {
		cl_page_list_init(&local_plist);
		plist = &local_plist;
		isize = 0; /* force commit only one page */
	}

	CDEBUG(D_READA, "%s: add 1 page [%lu, %lu]\n",
		file_dentry(file)->d_name.name, page_idx, page_idx);

	cl_page_assume(env, io, page);
	cl_page_list_add(plist, page);

	if (pio_enabled || isize == 0)
		GOTO(out_commit, rc = 0);

	end_idx = (isize - 1) >> PAGE_SHIFT;
	ra_idx = page_idx + ras->ras_consecutive_pages / 2;
	for (page_idx++; nr_pages < ras->ras_window_size - 1; page_idx++) {
		if (page_idx > end_idx)
			break;

		rcu_read_lock();
		vmpage = radix_tree_lookup(&mapping->page_tree, page_idx);
		rcu_read_unlock();

		if (vmpage && !radix_tree_exceptional_entry(vmpage))
			continue;

#ifdef HAVE_READAHEAD_GFP_MASK
		vmpage = __page_cache_alloc(readahead_gfp_mask(mapping));
#else
		vmpage = page_cache_alloc_readahead(mapping);
#endif
		if (!vmpage)
			break;

		if (page_idx == ra_idx)
			SetPageReadahead(vmpage);

		vmpage->index = page_idx;
		list_add(&vmpage->lru, &pages);
		nr_pages++;
	}

	if (nr_pages) {
		rc = ll_readpages(file, mapping, &pages, nr_pages);
		/* Clean up unused pages */
		put_pages_list(&pages);
	}

	/* fix read ahead state */
	if (page_idx < file->f_ra.size) {
		file->f_ra.size = page_idx;
		file->f_ra.async_size = file->f_ra.size;
	}
	file->f_ra.start = page_idx - file->f_ra.size;

out_commit:
	rc = vvp_io_read_commit(env, io, plist);
	RETURN(rc);

out_page_put:
	cl_page_put(env, page);
out_unlock:
	unlock_page(vmpage);
	RETURN(rc);
}

struct ll_readpages_desc {
	const struct lu_env	*rpd_env;
	struct cl_io		*rpd_io;
	struct file		*rpd_file;
	struct address_space	*rpd_mapping;
	struct cl_read_ahead	*rpd_ra;
};

static int ll_readpages_filler(void *data, struct page *vmpage)
{
	struct ll_readpages_desc *desc = data;
	const struct lu_env *env = desc->rpd_env;
	struct vvp_io *vio = vvp_env_io(env);
	struct cl_io *io = desc->rpd_io;
	struct cl_object *clob = io->ci_obj;
	struct file *file = desc->rpd_file;
	struct cl_read_ahead *ra = desc->rpd_ra;
	struct cl_page_list *plist = &vio->u.read.vui_plist;
	struct cl_page *page;
	pgoff_t page_idx = vmpage->index;
	__u32 rpc_pages = PTLRPC_MAX_BRW_PAGES;
	int rc = 0;
	ENTRY;

	if (ra->cra_end == 0 || page_idx > ra->cra_end) {
		cl_read_ahead_release(env, ra);

		rc = cl_io_read_ahead(env, io, page_idx, ra);
		if (rc)
			GOTO(out_unlock, rc);

		CDEBUG(D_READA, "%s: CLIO readahead: page offset: %lu, "
			"cra_end: %lu, cra_rpc_size: %u\n",
			file_dentry(file)->d_name.name,
			page_idx, ra->cra_end, ra->cra_rpc_size);

		if (page_idx > ra->cra_end)
			GOTO(out_unlock, rc = 0);
	}

	page = cl_page_find(env, clob, page_idx, vmpage, CPT_CACHEABLE);
	if (unlikely(IS_ERR(page)))
		GOTO(out_unlock, rc = PTR_ERR(page));

	LASSERT(page->cp_type == CPT_CACHEABLE);

	/* Page from a non-object file */
	if (unlikely(PageUptodate(vmpage)))
		GOTO(out_page_put, rc = 0);

	cl_page_assume(env, io, page);
	cl_page_list_add(plist, page);

	if (ra->cra_rpc_size)
		rpc_pages = ra->cra_rpc_size;
	/* We may have one full RPC, commit it soon */
	if (plist->pl_nr >= rpc_pages)
		rc = vvp_io_read_commit(env, io, plist);

	RETURN(rc);

out_page_put:
	cl_page_put(env, page);
out_unlock:
	unlock_page(vmpage);
	RETURN(rc);
}

struct ll_readpages_pt {
	struct cfs_ptask	 lrp_task;
	struct ll_readpages_desc lrp_desc;
	struct list_head	 lrp_pages;
	size_t			 lrp_chunk_size;
};

#define lru_to_first_page(head) (list_entry((head)->prev, struct page, lru))
#define lru_to_last_page(head)  (list_entry((head)->next, struct page, lru))

static int ll_readpages_ptask(struct cfs_ptask *ptask);

static ssize_t ll_readpages_submit(struct file *file,
				   struct address_space *mapping,
				   struct list_head *pages,
				   size_t chunk_size,
				   int cb_cpu)
{
	struct ll_readpages_pt *pt;
	size_t nr_pages = 0;
	int rc = 0;

	if (list_empty(pages))
		RETURN(0);

	pt = kmalloc(sizeof(*pt), GFP_NOFS | __GFP_NORETRY | __GFP_NOWARN);
	if (pt == NULL)
		RETURN(-ENOMEM);

	get_file(file);
	pt->lrp_desc.rpd_file = file;
	pt->lrp_desc.rpd_mapping = mapping;
	INIT_LIST_HEAD(&pt->lrp_pages);
	pt->lrp_chunk_size = chunk_size;

	while (!list_empty(pages)) {
		struct page *vmpage = lru_to_first_page(pages);

		list_del(&vmpage->lru);
		list_add(&vmpage->lru, &pt->lrp_pages);
		nr_pages++;
	}

	rc = cfs_ptask_init(&pt->lrp_task, ll_readpages_ptask, pt,
			    PTF_AUTOFREE, cb_cpu);
	if (!rc)
		rc = cfs_ptask_submit(&pt->lrp_task, vvp_ra_engine);

	if (rc) {
		/* Clean up unused pages */
		put_pages_list(&pt->lrp_pages);
		fput(file);
		kfree(pt);
	}

	RETURN(rc < 0 ? rc : nr_pages);
}

enum readahead_request {
	RAR_SERIAL = 0,
	RAR_ASYNC  = 1,
	RAR_SYNC   = 2,
};

/**
 * Move several pages from whole list of @pages into @chunk_pages.
 * The chunk_size is used as a hint to understand how many pages will be
 * sufficient to create one chunk. If count of pages in this chunk more than
 * chunk_size the boundary is checked to complete it. The boundary of chunk is
 * RPC size or stripe size. If original pages are not enough for full RPC or
 * stripe add more pages until boundary.
 */
static ssize_t ll_readpages_prepare_chunk(struct ll_readpages_desc *desc,
					  struct list_head *pages,
					  struct list_head *chunk_pages,
					  size_t *pchunk_size,
					  enum readahead_request rar)
{
	const char *reason;
	const struct lu_env *env = desc->rpd_env;
	struct cl_io *io = desc->rpd_io;
	struct vvp_io *vio = vvp_env_io(env);
	struct address_space *mapping = desc->rpd_mapping;
	struct cl_read_ahead *ra = desc->rpd_ra;
	struct file *file = desc->rpd_file;
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_readahead_state *ras = &fd->fd_ras;
	struct inode *inode = file_inode(file);
	struct ll_sb_info *sbi = ll_i2sbi(inode);
	struct page *vmpage = NULL;
	size_t nr_pages = 0;
	size_t reserved = vio->u.read.vui_plist.pl_nr;
	pgoff_t page_idx = 0;
	pgoff_t ra_idx = 0;
	pgoff_t end_idx;
	loff_t isize = i_size_read(inode);
	__u32 rpc_pages = 0;
	int nr_ra_calls = 0;
	unsigned long next_ra_pos;
	unsigned long next_stride = 0;
	unsigned long stride_gap;
	bool ra_set = false;
	int rc;

	if (isize == 0)
		RETURN(0);

	end_idx = (isize - 1) >> PAGE_SHIFT;

	spin_lock(&ras->ras_lock);
	stride_gap = ras->ras_stride_length > ras->ras_stride_pages ?
		     ras->ras_stride_length - ras->ras_stride_pages : 0;
	if (ras->ras_consecutive_stride_requests > 1 &&
	    stride_gap && ras->ras_stride_length) {
		next_ra_pos = file->f_ra.start + file->f_ra.size;
		next_stride = ras->ras_stride_offset;
		while (next_stride < next_ra_pos)
			next_stride += ras->ras_stride_length;
		ras->ras_window_size = ras->ras_stride_pages;
	}
	spin_unlock(&ras->ras_lock);

next_chunk:
	reason = "end of pages";
	while (!list_empty(pages)) {
		bool out_of_stride = false;

		vmpage = lru_to_first_page(pages);
		page_idx = vmpage->index;
		list_del(&vmpage->lru);
		if (!ra_idx && PageReadahead(vmpage))
			ra_idx = page_idx;
		if (next_stride) {
			unsigned long stride_offset = ras->ras_stride_offset;
			unsigned long stride_length = ras->ras_stride_length;

			while (page_idx >= stride_offset + stride_length)
				stride_offset += stride_length;

			if (page_idx >= stride_offset + ras->ras_stride_pages)
				out_of_stride = true;
		}
		if (page_idx < ras->ras_last_readpage || out_of_stride) {
			if (ra_idx == page_idx) {
				ClearPageReadahead(vmpage);
				ra_set = true;
			}
			ClearPageFsCache(vmpage);
			put_page(vmpage);
			vmpage = NULL;
			goto check_for_more;
		}
		list_add(&vmpage->lru, chunk_pages);
		nr_pages++;

check_for_enough:
		if (page_idx >= end_idx) {
			reason = "EOF";
			break;
		}

		if (ra->cra_end == 0 || page_idx > ra->cra_end) {
			cl_read_ahead_release(env, ra);

			rc = cl_io_read_ahead(env, io, page_idx, ra);
			if (rc) {
				/* Clean up unused pages */
				put_pages_list(pages);
				reason = "cl_io_read_ahead()";
				break;
			}

			nr_ra_calls++;
			if (ra->cra_rpc_size)
				rpc_pages = ra->cra_rpc_size;

			/* Correct the chunk size according RPC size */
			if (*pchunk_size < rpc_pages)
				*pchunk_size = rpc_pages;

			CDEBUG(D_READA, "%s: CLIO readahead: page offset: %lu, "
				"cra_end: %lu, rpc_pages: %u, chunk_size: %zu, "
				"nr_pages: %zu\n",
				file_dentry(file)->d_name.name, page_idx,
				ra->cra_end, rpc_pages, *pchunk_size, nr_pages);

			if (page_idx > ra->cra_end) {
				reason = "CLIO break";
				break;
			}
		}

		if (nr_pages + reserved >= *pchunk_size) {
			if (page_idx == ra->cra_end) {
				reason = "stripe boundary";
				break;
			}
			if (rpc_pages && !((nr_pages + reserved) % rpc_pages)) {
				reason = "RPC boundary";
				break;
			}
		}

check_for_more:
		if (list_empty(pages) && rar != RAR_SYNC) {
			/* Add one more page until RPC or stripe boundary */
			rcu_read_lock();
			vmpage = radix_tree_lookup(&mapping->page_tree,
						   page_idx + 1);
			rcu_read_unlock();
			if (vmpage && !radix_tree_exceptional_entry(vmpage)) {
				reason = "radix_tree_lookup()";
				break;
			}

#ifdef HAVE_READAHEAD_GFP_MASK
			vmpage = __page_cache_alloc(readahead_gfp_mask(mapping));
#else
			vmpage = page_cache_alloc_readahead(mapping);
#endif
			if (!vmpage) {
				reason = "page_cache_alloc_readahead()";
				break;
			}

			vmpage->index = ++page_idx;
			list_add(&vmpage->lru, chunk_pages);
			nr_pages++;

			file->f_ra.size++;
			file->f_ra.async_size++;

			goto check_for_enough;
		}
	}

	if (ra_set && vmpage) {
		SetPageReadahead(vmpage);
		ra_idx = page_idx;
	}

	CDEBUG(D_READA, "%s: %s, page offset: (%lu) %lu of %lu, cra_end: %lu, "
		"rpc_pages: %u, chunk_size: %zu, nr_pages: %zu\n",
		file_dentry(file)->d_name.name, reason, ra_idx, page_idx,
		end_idx, ra->cra_end, rpc_pages, *pchunk_size, nr_pages);

	if (list_empty(pages) &&
	    page_idx < end_idx &&
	    end_idx < sbi->ll_ra_info.ra_max_read_ahead_whole_pages) {
		reason = "EOF";
		while (page_idx < end_idx) {
			rcu_read_lock();
			vmpage = radix_tree_lookup(&mapping->page_tree,
						   page_idx + 1);
			rcu_read_unlock();
			if (vmpage && !radix_tree_exceptional_entry(vmpage)) {
				reason = "radix_tree_lookup()";
				break;
			}

#ifdef HAVE_READAHEAD_GFP_MASK
			vmpage = __page_cache_alloc(readahead_gfp_mask(mapping));
#else
			vmpage = page_cache_alloc_readahead(mapping);
#endif
			if (!vmpage) {
				reason = "page_cache_alloc_readahead()";
				break;
			}

			vmpage->index = ++page_idx;
			list_add(&vmpage->lru, pages);

			file->f_ra.size++;
			file->f_ra.async_size++;
		}

		CDEBUG(D_READA, "%s: %s, whole file: %lu of %lu\n",
			file_dentry(file)->d_name.name, reason,
			page_idx, end_idx);
	}

	if (rar == RAR_SERIAL && !list_empty(pages))
		goto next_chunk;

	if (next_stride && ra_idx >= file->f_ra.start) {
		/* tune in-kernel readahead according RA state */
		next_ra_pos = file->f_ra.start + file->f_ra.size;
		if (next_stride > next_ra_pos) {
			file->f_ra.size += next_stride - next_ra_pos;
			file->f_ra.async_size = next_stride - ra_idx;

			CDEBUG(D_READA, "%s: move next read ahead position "
				"from %lu to %lu\n",
				file_dentry(file)->d_name.name, next_ra_pos,
				file->f_ra.start + file->f_ra.size);
		}
	}

	if (nr_ra_calls > 1)
		cl_read_ahead_release(env, ra);

	RETURN(nr_pages);
}

static int ll_readpages_ptask(struct cfs_ptask *ptask)
{
	struct list_head chunk_pages;
	struct ll_readpages_pt *pt = ptask->pt_cbdata;
	struct address_space *mapping = pt->lrp_desc.rpd_mapping;
	struct file *file = pt->lrp_desc.rpd_file;
	struct lu_env *env;
	struct vvp_io *vio;
	struct cl_io *io;
	struct cl_read_ahead ra = { 0 };
	ssize_t nr_chunk_pages = 0;
	ssize_t nr_submit_pages = 0;
	int rc;
	__u16 refcheck;
	ENTRY;

	CDEBUG(D_READA, "%s: request pages [%lu, %lu]\n",
		file_dentry(file)->d_name.name,
		lru_to_first_page(&pt->lrp_pages)->index,
		lru_to_last_page(&pt->lrp_pages)->index);

	env = cl_env_get(&refcheck);
	if (IS_ERR(env)) {
		/* Clean up unused pages */
		put_pages_list(&pt->lrp_pages);
		fput(file);
		RETURN(PTR_ERR(env));
	}

	io = vvp_env_thread_io(env);
	ll_io_init(io, file, io->ci_type);
	io->ci_ndelay_tried = 0;

	rc = cl_io_rw_init(env, io, CIT_READ, 0, OBD_OBJECT_EOF);
	if (rc)
		GOTO(out_io_fini, rc = io->ci_result);

	vio = vvp_env_io(env);
	vio->vui_fd = LUSTRE_FPRIVATE(file);
	vio->vui_io_subtype = IO_NORMAL;

	ll_cl_add(file, env, io);
	rc = cl_io_iter_init(env, io);
	if (rc)
		GOTO(out_iter_fini, rc);

	/* SKIP: cl_io_lock() and cl_io_start() */
	io->ci_state = CIS_IO_GOING;

	pt->lrp_desc.rpd_env = env;
	pt->lrp_desc.rpd_io  = io;
	pt->lrp_desc.rpd_ra  = &ra;

	INIT_LIST_HEAD(&chunk_pages);
	nr_chunk_pages = ll_readpages_prepare_chunk(&pt->lrp_desc,
						    &pt->lrp_pages,
						    &chunk_pages,
						    &pt->lrp_chunk_size,
						    RAR_ASYNC);
	if (nr_chunk_pages < 0) {
		/* Clean up unused pages */
		put_pages_list(&chunk_pages);
		GOTO(out_io, rc = nr_chunk_pages);
	}

	nr_submit_pages = ll_readpages_submit(file, mapping, &pt->lrp_pages,
					      pt->lrp_chunk_size,
					      ptask->pt_cbcpu);
	if (nr_submit_pages > 0) {
		rc = lustre_readpages_from_fscache(file_inode(file), mapping,
					   &chunk_pages, (unsigned int *)&nr_submit_pages);
		if (rc == 0)
			GOTO(out_io, rc);
	}

	if (nr_submit_pages > 0)
		CDEBUG(D_READA, "%s: submit %ld pages to other thread\n",
			file_dentry(file)->d_name.name, nr_submit_pages);

	if (nr_chunk_pages > 0) {
		CDEBUG(D_READA, "%s: process %ld pages "
			"in this thread [%lu, %lu]\n",
			file_dentry(file)->d_name.name, nr_chunk_pages,
			lru_to_first_page(&chunk_pages)->index,
			lru_to_last_page(&chunk_pages)->index);

		rc = read_cache_pages(mapping, &chunk_pages,
				      ll_readpages_filler, &pt->lrp_desc);
		if (rc)
			/* Clean up unused pages */
			put_pages_list(&chunk_pages);
		rc = vvp_io_read_commit(env, io, &vio->u.read.vui_plist);
	}

out_io:
	cl_read_ahead_release(env, &ra);
	/* SKIP: cl_io_end() and cl_io_unlock() */
	io->ci_state = CIS_UNLOCKED;

out_iter_fini:
	cl_io_iter_fini(env, io);
	ll_cl_remove(file, env);

out_io_fini:
	/* This is async thread and it should not modify anything.
	 * All those changes will be done in main I/O thread after
	 * page cache miss. */
	io->ci_restore_needed = 0;
	io->ci_need_restart   = 0;
	io->ci_verify_layout  = 0;

	cl_io_fini(env, io);

	/* Clean up unused pages */
	put_pages_list(&pt->lrp_pages);
	fput(file);

	cl_env_put(env, &refcheck);
	RETURN(rc);
}

int ll_readpages(struct file *file, struct address_space *mapping,
		 struct list_head *pages, unsigned int nr_pages)
{
	LIST_HEAD(chunk_pages);
	struct cl_read_ahead ra = { 0 };
	struct ll_readpages_desc desc = { .rpd_ra = &ra };
	struct page *first_page = lru_to_first_page(pages);
	struct page *last_page = lru_to_last_page(pages);
	struct inode *inode = file_inode(file);
	struct ll_file_data *fd = LUSTRE_FPRIVATE(file);
	struct ll_readahead_state *ras = &fd->fd_ras;
	struct ll_cl_context *lcc;
	const struct lu_env *env;
	struct cl_io *io;
	ssize_t nr_chunk_pages = 0;
	ssize_t nr_submit_pages = 0;
	int weight = max(1, min(cfs_ptengine_weight(vvp_ra_engine),
				cfs_cpt_number(cfs_cpt_table)));
	size_t chunk_size = max((unsigned long)nr_pages, ras->ras_window_size)
			    / weight;
	bool pio_enabled = !!(ll_i2sbi(inode)->ll_flags & LL_SBI_PIO);
	int rc = -ENODATA;
	ENTRY;

	lcc = ll_cl_find(file);
	if (lcc == NULL || lcc->lcc_io == NULL) {
		/* fast read: page cache miss */
		if (!pio_enabled) {
			CDEBUG(D_READA, "%s: drop async %u pages [%lu, %lu]\n",
				file_dentry(file)->d_name.name, nr_pages,
				first_page->index, last_page->index);

			spin_lock(&ras->ras_lock);
			if (nr_pages > ras->ras_window_size)
				ras->ras_window_size = nr_pages;
			spin_unlock(&ras->ras_lock);

			RETURN(-ENODATA);
		}

		nr_submit_pages = ll_readpages_submit(file, mapping, pages,
						      chunk_size,
						      smp_processor_id());
		if (nr_submit_pages > 0) {
			CDEBUG(D_READA, "%s: submit async %zd of %u pages "
				"[%lu, %lu]\n",
				file_dentry(file)->d_name.name, nr_submit_pages,
				nr_pages, first_page->index, last_page->index);
		}

		RETURN(-ENODATA);
	}

	LASSERT(lcc->lcc_io->ci_state == CIS_IO_GOING);

	env = lcc->lcc_env;
	io  = lcc->lcc_io;

	if (pio_enabled && first_page->index <= ras->ras_next_readahead) {
		CDEBUG(D_READA, "%s: drop sync %u pages [%lu, %lu]\n",
			file_dentry(file)->d_name.name, nr_pages,
			first_page->index, last_page->index);

		GOTO(out, rc = -ENODATA);
	}

	desc.rpd_env = env;
	desc.rpd_io  = io;
	desc.rpd_file = file;
	desc.rpd_mapping = mapping;

	CDEBUG(D_READA, "%s: request %u pages [%lu, %lu]\n",
		file_dentry(file)->d_name.name, nr_pages,
		first_page->index, last_page->index);

	if (!pio_enabled || first_page->index <= ras->ras_next_readahead) {
		/* get pages for sync processing */
		nr_chunk_pages = ll_readpages_prepare_chunk(&desc, pages,
							    &chunk_pages,
							    &chunk_size,
							    pio_enabled ?
							    RAR_SYNC :
							    RAR_SERIAL);
		if (nr_chunk_pages < 0) {
			/* Clean up unused pages */
			put_pages_list(&chunk_pages);
			GOTO(out, rc = nr_chunk_pages);
		}
	}

	if (pio_enabled && !list_empty(pages) && io->ci_ndelay_tried == 0) {
		nr_submit_pages = ll_readpages_submit(file, mapping, pages,
						      chunk_size,
						      smp_processor_id());
		if (nr_submit_pages > 0)
			CDEBUG(D_READA, "%s: submit %ld of %u pages "
				"to other thread\n",
				file_dentry(file)->d_name.name,
				nr_submit_pages, nr_pages);
	}

	rc = lustre_readpages_from_fscache(inode, mapping, &chunk_pages,
					   (unsigned int *)&nr_chunk_pages);
	if (rc == 0)
		GOTO(out, rc);

	if (nr_chunk_pages > 0) {
		struct cl_page_list *plist = &vvp_env_io(env)->u.read.vui_plist;

		CDEBUG(D_READA, "%s: process %ld of %u pages "
			"in this thread [%lu, %lu]\n",
			file_dentry(file)->d_name.name, nr_chunk_pages,
			nr_pages, lru_to_first_page(&chunk_pages)->index,
			lru_to_last_page(&chunk_pages)->index);

		rc = read_cache_pages(mapping, &chunk_pages,
				      ll_readpages_filler, &desc);
		if (rc)
			/* Clean up unused pages */
			put_pages_list(&chunk_pages);
		rc = vvp_io_read_commit(env, io, plist);
	}

out:
	cl_read_ahead_release(env, &ra);
	RETURN(rc);
}
