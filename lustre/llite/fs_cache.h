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
 * Copyright (c) 2017, DataDirect Networks Storage
 */
/*
 * This file is part of Lustre, http://www.lustre.org/
 * Lustre is a trademark of Sun Microsystems, Inc.
 *
 * lustre/llite/fs_cache.h
 *
 * Author: Wang Shilong <wshilong@ddn.com>
 */

#ifndef _LUSTRE_FS_CACHE_H
#define _LUSTRE_FS_CACHE_H
#include <linux/fscache.h>
#include <linux/spinlock.h>
#include "llite_internal.h"

extern struct fscache_netfs lustre_cache_netfs;
extern const struct fscache_cookie_def lustre_cache_session_index_def;
extern const struct fscache_cookie_def lustre_cache_inode_index_def;

extern void lustre_cache_session_get_cookie(struct super_block *sb);
extern void lustre_cache_session_put_cookie(struct super_block *sb);

extern void lustre_fscache_init_inode(struct inode *inode);
extern void lustre_fscache_evict_inode(struct inode *inode);
extern void lustre_fscache_release_inode(struct inode *inode);
extern void lustre_fscache_open_file(struct inode *inode, struct file *filp);

extern int __lustre_fscache_release_page(struct page *page, gfp_t gfp);
extern void __lustre_fscache_invalidate_page(struct page *page);
extern int __lustre_readpage_from_fscache(struct inode *inode,
					struct page *page);
extern void __lustre_readpage_to_fscache(struct inode *inode, struct page *page);
extern void __lustre_fscache_wait_on_page_write(struct inode *inode,
					      struct page *page);

static inline int lustre_fscache_release_page(struct page *page,
					    gfp_t gfp)
{
	return __lustre_fscache_release_page(page, gfp);
}

static inline void lustre_fscache_invalidate_page(struct page *page)
{
	__lustre_fscache_invalidate_page(page);
}

static inline int lustre_readpage_from_fscache(struct inode *inode,
					     struct page *page)
{
	return __lustre_readpage_from_fscache(inode, page);
}

static inline void lustre_readpage_to_fscache(struct inode *inode,
					    struct page *page)
{
	/* readahead thread might make us to skip mark it cached */
	SetPageFsCache(page);

	if (PageFsCache(page))
		__lustre_readpage_to_fscache(inode, page);
}

static inline void lustre_uncache_page(struct inode *inode, struct page *page)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);
	fscache_uncache_page(ll_info->fscache, page);
	BUG_ON(PageFsCache(page));
}

static inline void lustre_fscache_wait_on_page_write(struct inode *inode,
						   struct page *page)
{
	return __lustre_fscache_wait_on_page_write(inode, page);
}
#endif /* _LUSTRE_FS_CACHE_H */
