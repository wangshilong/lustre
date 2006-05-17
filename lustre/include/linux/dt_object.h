/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (C) 2006 Cluster File Systems, Inc.
 *
 *   This file is part of Lustre, http://www.lustre.org.
 *
 *   Lustre is free software; you can redistribute it and/or
 *   modify it under the terms of version 2 of the GNU General Public
 *   License as published by the Free Software Foundation.
 *
 *   Lustre is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Lustre; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef __LINUX_DT_OBJECT_H
#define __LINUX_DT_OBJECT_H

/*
 * Sub-class of lu_object with methods common for "data" objects in OST stack.
 *
 * Data objects behave like regular files: you can read/write them, get and
 * set their attributes. Implementation of dt interface is supposed to
 * implement some form of garbage collection, normally reference counting
 * (nlink) based one.
 *
 * Examples: osd (lustre/osd) is an implementation of dt interface.
 */


/*
 * super-class definitions.
 */
#include <linux/lu_object.h>

#include <libcfs/list.h>
#include <libcfs/kp30.h>

struct seq_file;
struct proc_dir_entry;
struct lustre_cfg;

struct thandle;
struct txn_param;
struct dt_device;
struct dt_object;

/*
 * Lock mode for DT objects.
 */
enum dt_lock_mode {
        DT_WRITE_LOCK = 1,
        DT_READ_LOCK  = 2,
};

/*
 * Operations on dt device.
 */
struct dt_device_operations {
        /*
         * Method for getting/setting device wide back stored config data,
         * like last used meta-sequence, etc.
         *
         * XXX this is ioctl()-like interface we want to get rid of.
         */
        int (*dt_config) (struct lu_context *ctx,
                          struct dt_device *dev, const char *name,
                          void *buf, int size, int mode);
        /*
         * Return device-wide statistics.
         */
        int   (*dt_statfs)(struct lu_context *ctx,
                           struct dt_device *dev, struct kstatfs *sfs);
        /*
         * Start transaction, described by @param.
         */
        struct thandle *(*dt_trans_start)(struct lu_context *ctx,
                                          struct dt_device *dev,
                                          struct txn_param *param);
        /*
         * Finish previously started transaction.
         */
        void  (*dt_trans_stop)(struct lu_context *ctx, struct thandle *th);
        /*
         * Return fid of root index object.
         */
        int   (*dt_root_get)(struct lu_context *ctx,
                             struct dt_device *dev, struct lu_fid *f);
};

/*
 * Per-dt-object operations.
 */
struct dt_object_operations {
        void  (*do_object_lock)(struct lu_context *ctx,
                                struct dt_object *dt, enum dt_lock_mode mode);
        void  (*do_object_unlock)(struct lu_context *ctx,
                                  struct dt_object *dt, enum dt_lock_mode mode);
        /*
         * Note: following ->do_{x,}attr_{set,get}() operations are very
         * similar to ->moo_{x,}attr_{set,get}() operations in struct
         * md_object_operations (see md_object.h). These operations are not in
         * lu_object_operations, because ->do_{x,}attr_set() versions take
         * transaction handle as an argument (this transaction is started by
         * caller). We might factor ->do_{x,}attr_get() into
         * lu_object_operations, but that would break existing symmetry.
         */

        /*
         * Return standard attributes.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_attr_get)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr);
        /*
         * Set standard attributes.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_attr_set)(struct lu_context *ctxt, struct dt_object *dt,
                             struct lu_attr *attr, struct thandle *handle);
        /*
         * Return a value of an extended attribute.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_xattr_get)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name);
        /*
         * Set value of an extended attribute.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int   (*do_xattr_set)(struct lu_context *ctxt, struct dt_object *dt,
                              void *buf, int buf_len, const char *name,
                              struct thandle *handle);
        /*
         * Create new object on this device.
         *
         * precondition: !lu_object_exists(ctxt, &dt->do_lu);
         * postcondition: ergo(result == 0, lu_object_exists(ctxt, &dt->do_lu));
         */
        int   (*do_object_create)(struct lu_context *ctxt, struct dt_object *dt,
                                  struct lu_attr *attr, struct thandle *th);
        /*
         * Destroy existing object.
         *
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         * postcondition: ergo(result == 0,
         *                     !lu_object_exists(ctxt, &dt->do_lu));
         */
        int   (*do_object_destroy)(struct lu_context *ctxt,
                                   struct dt_object *dt, struct thandle *th);
};

/*
 * Per-dt-object operations on "file body".
 */
struct dt_body_operations {
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_read)(struct lu_context *ctxt, struct dt_object *dt, ...);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_write)(struct lu_context *ctxt, struct dt_object *dt, ...);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dbo_truncate)(struct lu_context *ctxt, struct dt_object *dt, ...);
};

/*
 * Incomplete type of index record.
 */
struct dt_rec;

/*
 * Incomplete type of index key.
 */
struct dt_key;

struct dt_index_features {
        /* required feature flags from enum dt_index_flags */
        __u32 dif_flags;
        /* minimal required key size */
        size_t dif_keysize_min;
        /* maximal required key size, 0 if no limit */
        size_t dif_keysize_max;
        /* minimal required record size */
        size_t dif_recsize_min;
        /* maximal required record size, 0 if no limit */
        size_t dif_recsize_max;
};

enum dt_index_flags {
        /* index supports variable sized keys */
        DT_IND_VARKEY = 1 << 0,
        /* index supports variable sized records */
        DT_IND_VARREC = 1 << 1,
        /* index can be modified */
        DT_IND_UPDATE = 1 << 2,
        /* index supports records with non-unique (duplicate) keys */
        DT_IND_NONUNQ = 1 << 3
};

/*
 * Features, required from index to support file system directories (mapping
 * names to fids).
 */
extern const struct dt_index_features dt_directory_features;

/*
 * Per-dt-object operations on object as index.
 */
struct dt_index_operations {
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dio_lookup)(struct lu_context *ctxt, struct dt_object *dt,
                          struct dt_rec *rec, const struct dt_key *key);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dio_insert)(struct lu_context *ctxt, struct dt_object *dt,
                          const struct dt_rec *rec, const struct dt_key *key,
                          struct thandle *handle);
        /*
         * precondition: lu_object_exists(ctxt, &dt->do_lu);
         */
        int (*dio_delete)(struct lu_context *ctxt, struct dt_object *dt,
                          const struct dt_rec *rec, const struct dt_key *key,
                          struct thandle *handle);

        /*
         * Features probing. Returns 1 if this index supports all features in
         * @feat, -ve on error, 0 otherwise.
         */
        int (*dio_probe)(struct lu_context *ctxt, struct dt_object *dt,
                         const struct dt_index_features *feat);
};

struct dt_device {
        struct lu_device             dd_lu_dev;
        struct dt_device_operations *dd_ops;
        /*
         * List of dt_txn_callback (see below). This is not protected in any
         * way, because callbacks are supposed to be added/deleted only during
         * single-threaded start-up shut-down procedures.
         */
        struct list_head             dd_txn_callbacks;
};

int  dt_device_init(struct dt_device *dev, struct lu_device_type *t);
void dt_device_fini(struct dt_device *dev);

static inline int lu_device_is_dt(const struct lu_device *d)
{
        return ergo(d != NULL, d->ld_type->ldt_tags & LU_DEVICE_DT);
}

static inline struct dt_device * lu2dt_dev(struct lu_device *l)
{
        LASSERT(lu_device_is_dt(l));
        return container_of0(l, struct dt_device, dd_lu_dev);
}

struct dt_object {
        struct lu_object             do_lu;
        struct dt_object_operations *do_ops;
        struct dt_body_operations   *do_body_ops;
        struct dt_index_operations  *do_index_ops;
};

int  dt_object_init(struct dt_object *obj,
                    struct lu_object_header *h, struct lu_device *d);
void dt_object_fini(struct dt_object *obj);

struct txn_param {
        unsigned int tp_credits;
};

struct thandle {
        struct dt_device *th_dev;
};

/*
 * Transaction call-backs.
 *
 * These are invoked by osd (or underlying transaction engine) when
 * transaction changes state.
 *
 * Call-backs are used by upper layers to modify transaction parameters and to
 * perform some actions on for each transaction state transition. Typical
 * example is mdt registering call-back to write into last-received file
 * before each transaction commit.
 */
struct dt_txn_callback {
        int (*dtc_txn_start)(struct lu_context *ctx, struct dt_device *dev,
                             struct txn_param *param, void *cookie);
        int (*dtc_txn_stop)(struct lu_context *ctx, struct dt_device *dev,
                            struct thandle *txn, void *cookie);
        int (*dtc_txn_commit)(struct lu_context *ctx, struct dt_device *dev,
                              struct thandle *txn, void *cookie);
        void            *dtc_cookie;
        struct list_head dtc_linkage;
};

void dt_txn_callback_add(struct dt_device *dev, struct dt_txn_callback *cb);
void dt_txn_callback_del(struct dt_device *dev, struct dt_txn_callback *cb);

int dt_txn_hook_start(struct lu_context *ctx,
                      struct dt_device *dev, struct txn_param *param);
int dt_txn_hook_stop(struct lu_context *ctx,
                     struct dt_device *dev, struct thandle *txn);
int dt_txn_hook_commit(struct lu_context *ctx,
                       struct dt_device *dev, struct thandle *txn);

#endif /* __LINUX_DT_OBJECT_H */
