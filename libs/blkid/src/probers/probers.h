/*
 * probe.h - constants and on-disk structures for extracting device data
 *
 * Copyright (C) 1999 by Andries Brouwer
 * Copyright (C) 1999, 2000, 2003 by Theodore Ts'o
 * Copyright (C) 2001 by Andreas Dilger
 * Copyright (C) 2008 Karel Zak <kzak@redhat.com>
 *
 * %Begin-Header%
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 * %End-Header%
 */

#ifndef _BLKID_PROBE_H
#define _BLKID_PROBE_H

extern const struct blkid_idinfo cramfs_idinfo;
extern const struct blkid_idinfo swap_idinfo;
extern const struct blkid_idinfo swsuspend_idinfo;
extern const struct blkid_idinfo adraid_idinfo;
extern const struct blkid_idinfo ddfraid_idinfo;
extern const struct blkid_idinfo iswraid_idinfo;
extern const struct blkid_idinfo jmraid_idinfo;
extern const struct blkid_idinfo lsiraid_idinfo;
extern const struct blkid_idinfo nvraid_idinfo;
extern const struct blkid_idinfo pdcraid_idinfo;
extern const struct blkid_idinfo silraid_idinfo;
extern const struct blkid_idinfo viaraid_idinfo;
extern const struct blkid_idinfo linuxraid_idinfo;
extern const struct blkid_idinfo ext4dev_idinfo;
extern const struct blkid_idinfo ext4_idinfo;
extern const struct blkid_idinfo ext3_idinfo;
extern const struct blkid_idinfo ext2_idinfo;
extern const struct blkid_idinfo jbd_idinfo;
extern const struct blkid_idinfo jfs_idinfo;
extern const struct blkid_idinfo xfs_idinfo;
extern const struct blkid_idinfo gfs_idinfo;
extern const struct blkid_idinfo gfs2_idinfo;
extern const struct blkid_idinfo romfs_idinfo;
extern const struct blkid_idinfo ocfs_idinfo;
extern const struct blkid_idinfo ocfs2_idinfo;
extern const struct blkid_idinfo oracleasm_idinfo;
extern const struct blkid_idinfo reiser_idinfo;
extern const struct blkid_idinfo reiser4_idinfo;
extern const struct blkid_idinfo hfs_idinfo;
extern const struct blkid_idinfo hfsplus_idinfo;
extern const struct blkid_idinfo ntfs_idinfo;
extern const struct blkid_idinfo iso9660_idinfo;
extern const struct blkid_idinfo udf_idinfo;
extern const struct blkid_idinfo vfat_idinfo;
extern const struct blkid_idinfo lvm2_idinfo;
extern const struct blkid_idinfo luks_idinfo;
extern const struct blkid_idinfo highpoint37x_idinfo;
extern const struct blkid_idinfo highpoint45x_idinfo;

#endif /* _BLKID_PROBE_H */
