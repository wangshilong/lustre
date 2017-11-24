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
 * lustre/llite/fs_cache.c
 *
 * Author: Wang Shilong <wshilong@ddn.com>
 */

#include <linux/file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "fs_cache.h"
#include "llite_internal.h"

struct fscache_netfs lustre_cache_netfs = {
	.name 		= "lustre",
	.version 	= 0,
};

static uint16_t lustre_cache_session_get_key(const void *cookie_netfs_data,
					     void *buffer, uint16_t bufmax)
{
	const struct super_block *sb = cookie_netfs_data;
	struct lustre_sb_info *lsi = s2lsi(sb);

	uint16_t klen = strlen(lsi->lsi_lmd->lmd_dev);

	if (klen > bufmax)
		return 0;

	memcpy(buffer, lsi->lsi_lmd->lmd_dev, klen);
	return klen;
}

const struct fscache_cookie_def lustre_cache_session_index_def = {
	.name		= "lustre.session",
	.type		= FSCACHE_COOKIE_TYPE_INDEX,
	.get_key	= lustre_cache_session_get_key,
};

void lustre_cache_session_get_cookie(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	sbi->fscache = fscache_acquire_cookie(lustre_cache_netfs.primary_index,
					      &lustre_cache_session_index_def,
					      sb, true);
}

void lustre_cache_session_put_cookie(struct super_block *sb)
{
	struct ll_sb_info *sbi = ll_s2sbi(sb);

	if (sbi->fscache) {
		fscache_relinquish_cookie(sbi->fscache, 0);
		sbi->fscache = NULL;
	}
}

static uint16_t lustre_cache_inode_get_key(const void *cookie_netfs_data,
					   void *buffer, uint16_t bufmax)
{
	const struct ll_inode_info *ll_info = cookie_netfs_data;

	/* Any idea to make hardlink inode reuse same cache ?*/
	memcpy(buffer, &ll_info->lli_fid, sizeof(ll_info->lli_fid));
	return sizeof(ll_info->lli_fid);
}

static void lustre_cache_inode_get_attr(const void *cookie_netfs_data,
					uint64_t *size)
{
	const struct ll_inode_info *ll_info = cookie_netfs_data;
	*size = i_size_read(&ll_info->lli_vfs_inode);
}

struct lustre_fscache_inode_auxdata {
	struct timespec	mtime;
	struct timespec	ctime;
	loff_t		size;
	__u64		version;
};

static uint16_t lustre_cache_inode_get_aux(const void *cookie_netfs_data,
					   void *buffer, uint16_t buflen)
{
	struct lustre_fscache_inode_auxdata auxdata;
	const struct ll_inode_info *ll_info = cookie_netfs_data;

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata.size = ll_info->lli_vfs_inode.i_size;
	auxdata.mtime = ll_info->lli_vfs_inode.i_mtime;
	auxdata.ctime = ll_info->lli_vfs_inode.i_ctime;
	auxdata.version = ll_info->lli_vfs_inode.i_version;

	if (buflen > sizeof(auxdata))
		buflen = sizeof(auxdata);

	memcpy(buffer, &auxdata, buflen);
	return buflen;
}

static enum
fscache_checkaux lustre_cache_inode_check_aux(void *cookie_netfs_data,
					      const void *buffer,
					      uint16_t buflen)
{
	struct lustre_fscache_inode_auxdata auxdata;
	struct ll_inode_info *ll_info = cookie_netfs_data;

	if (buflen != sizeof(auxdata))
		return FSCACHE_CHECKAUX_OBSOLETE;

	memset(&auxdata, 0, sizeof(auxdata));
	auxdata.size = ll_info->lli_vfs_inode.i_size;
	auxdata.mtime = ll_info->lli_vfs_inode.i_mtime;
	auxdata.ctime = ll_info->lli_vfs_inode.i_ctime;
	auxdata.version = ll_info->lli_vfs_inode.i_version;

	if (memcmp(buffer, &auxdata, buflen) != 0)
		return FSCACHE_CHECKAUX_OBSOLETE;

	return FSCACHE_CHECKAUX_OKAY;
}

const struct fscache_cookie_def lustre_cache_inode_index_def = {
	.name		= "lustre.inode",
	.type		= FSCACHE_COOKIE_TYPE_DATAFILE,
	.get_key	= lustre_cache_inode_get_key,
	.get_attr	= lustre_cache_inode_get_attr,
	.get_aux	= lustre_cache_inode_get_aux,
	.check_aux	= lustre_cache_inode_check_aux,
};

/*
 * Initialise the per-inode cache cookie pointer for an Lustre inode.
 */
void lustre_fscache_init_inode(struct inode *inode)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);
	struct ll_sb_info *sbi = ll_s2sbi(inode->i_sb);

	ll_info->fscache = NULL;
	if (!S_ISREG(inode->i_mode))
		return;

	ll_info->fscache = fscache_acquire_cookie(sbi->fscache,
						  &lustre_cache_inode_index_def,
						  ll_info, false);
}
/*
 * Release a per-inode cookie.
 */
void lustre_fscache_release_inode(struct inode *inode)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);

	fscache_relinquish_cookie(ll_info->fscache, 0);
	ll_info->fscache = NULL;
}

void lustre_fscache_evict_inode(struct inode *inode)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);

	fscache_relinquish_cookie(ll_info->fscache, 1);
	ll_info->fscache = NULL;
}

static bool lustre_fscache_can_enable(void *data)
{
	struct inode *inode = data;

	return !inode_is_open_for_write(inode);
}

void lustre_fscache_open_file(struct inode *inode, struct file *filp)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);

	if (!fscache_cookie_valid(ll_info->fscache))
		return;

	if (inode_is_open_for_write(inode)) {
		fscache_disable_cookie(ll_info->fscache, true);
		fscache_uncache_all_inode_pages(ll_info->fscache, inode);
	} else {
		fscache_enable_cookie(ll_info->fscache, lustre_fscache_can_enable, inode);
	}
}

int __lustre_fscache_release_page(struct page *page, gfp_t gfp)
{
	struct inode *inode = page->mapping->host;
	struct ll_inode_info *ll_info = ll_i2info(inode);

	if (PageFsCache(page))
		return fscache_maybe_release_page(ll_info->fscache, page, gfp);

	return 1;
}

void __lustre_fscache_invalidate_page(struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct ll_inode_info *ll_info = ll_i2info(inode);

	if (PageFsCache(page)) {
		BUG_ON(!ll_info->fscache);
		fscache_wait_on_page_write(ll_info->fscache, page);
		BUG_ON(!PageLocked(page));
		fscache_uncache_page(ll_info->fscache, page);
	}
}

static void lustre_vfs_readpage_complete(struct page *page, void *data,
					 int error)
{
	if (!error)
		SetPageUptodate(page);

	unlock_page(page);
}

/**
 * __lustre_readpage_from_fscache - read a page from cache
 *
 * Returns 0 if the pages are in cache and a BIO is submitted,
 * 1 if the pages are not in cache and -error otherwise.
 */

int __lustre_readpage_from_fscache(struct inode *inode, struct page *page)
{
	int ret;
	struct ll_inode_info *ll_info = ll_i2info(inode);

	if (!ll_info->fscache)
		return -ENOBUFS;

	ret = fscache_read_or_alloc_page(ll_info->fscache,
					 page,
					 lustre_vfs_readpage_complete,
					 NULL,
					 GFP_KERNEL);
	switch (ret) {
	case -ENOBUFS:
	case -ENODATA:
		/* inode/page not in cache */
		return 1;
	case 0:
		/* BIO submitted */
		return ret;
	default:
		return ret;
	}
}

/**
 * __lustre_readpage_to_fscache - write a page to the cache
 *
 */
void __lustre_readpage_to_fscache(struct inode *inode, struct page *page)
{
	int ret;
	struct ll_inode_info *ll_info = ll_i2info(inode);

	ret = fscache_write_page(ll_info->fscache, page, GFP_KERNEL);
	if (ret != 0)
		lustre_uncache_page(inode, page);
}

/*
 * wait for a page to complete writing to the cache
 */
void __lustre_fscache_wait_on_page_write(struct inode *inode, struct page *page)
{
	struct ll_inode_info *ll_info = ll_i2info(inode);
	if (PageFsCache(page))
		fscache_wait_on_page_write(ll_info->fscache, page);
}
