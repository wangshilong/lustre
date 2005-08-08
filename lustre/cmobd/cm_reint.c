/* -*- mode: c; c-basic-offset: 8; indent-tabs-mode: nil; -*-
 * vim:expandtab:shiftwidth=8:tabstop=8:
 *
 *  Copyright (c) 2002 Cluster File Systems, Inc. <info@clusterfs.com>
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
 */

#define DEBUG_SUBSYSTEM S_CMOBD

#include <linux/version.h>
#include <linux/init.h>
#include <linux/obd_support.h>
#include <linux/lustre_lib.h>
#include <linux/lustre_net.h>
#include <linux/lustre_idl.h>
#include <linux/obd_class.h>
#include <linux/lustre_log.h>
#include <linux/lustre_cmobd.h>
#include <linux/lustre_fsfilt.h>
#include <linux/lustre_smfs.h>

#include "cm_internal.h"

#define OSS_REINT(opcode)      \
({                             \
    int _opcode = (opcode);    \
                               \
    (_opcode == OST_CREATE  || \
     _opcode == OST_SETATTR || \
     _opcode == OST_WRITE);    \
})

#define MDS_REINT(opcode)      \
    ((opcode) == MDS_REINT)

static int cmobd_reint_record(struct obd_device *obd, 
                              void *record, int opcode)
{
        if (OSS_REINT(opcode))
                return cmobd_reint_oss(obd, record, opcode);
        
        if (MDS_REINT(opcode))
                return cmobd_reint_mds(obd, record, opcode);

        CERROR("unrecognized reint opcode %d\n", opcode);
        return -EINVAL;
}

static int cmobd_reint_cb(struct llog_handle *llh, 
                          struct llog_rec_hdr *rec,
                          void *data)
{
        struct obd_device *obd = (struct obd_device*)data;
        char *buf, *pbuf;
        int rc = 0, opcode;
        
        ENTRY;

        if (!(llh->lgh_hdr->llh_flags & LLOG_F_IS_PLAIN)) {
                CERROR("log is not plain log\n");
                RETURN(-EINVAL);
        }
        
        if (rec->lrh_type != SMFS_UPDATE_REC)
		RETURN(-EINVAL);

        buf = (char *)(rec + 1);
        rc = smfs_rec_unpack(NULL, buf, &pbuf, &opcode);
        if (rc)
                GOTO(out, rc);

        rc = cmobd_reint_record(obd, pbuf, opcode); 
        if (rc)
                GOTO(out, rc);

        /* delete this record. */
        rc = LLOG_DEL_RECORD; 
out:
        RETURN(rc);
}

int cmobd_reintegrate(struct obd_device *obd)
{
        struct cm_obd *cmobd = &obd->u.cm;
        struct llog_ctxt *ctxt = NULL;
        struct llog_handle *llh;
        __u32 val_size;
        int rc = 0;
        ENTRY;

        /* XXX just fetch the reintegration log context from
         * cache ost directly, use logid later ?? */
        val_size = sizeof(ctxt);
        rc = obd_get_info(cmobd->cache_exp, strlen("reint_log") + 1,
                          "reint_log", &val_size, &ctxt);
        if (rc)
                RETURN(rc);

        /* use the already opened log handle instead of reopen a new log
         * handle */
        llh = ctxt ? ctxt->loc_handle : NULL;
        if (llh == NULL) {
                CERROR("reint log is not found, wrong fstype "
                       "or smfs plugin is used.\n");
                RETURN(-EINVAL);
        }

        /* FIXME: should we insert a LLOG_GEN_REC before process log? */
        rc = llog_cat_process(llh, (llog_cb_t)cmobd_reint_cb, obd);
        RETURN(rc);
}
