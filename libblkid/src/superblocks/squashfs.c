/*
 * Copyright (C) 2008 Karel Zak <kzak@redhat.com>
 *
 * Inspired by libvolume_id by
 *     Kay Sievers <kay.sievers@vrfy.org>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "bitops.h"	/* swab16() */
#include "superblocks.h"

struct sqsh_super_block {
	uint32_t	magic;
	uint32_t	inode_count;
	uint32_t	mod_time;
	uint32_t	block_size;
	uint32_t	frag_count;
	uint16_t	compressor;
	uint16_t	block_log;
	uint16_t	flags;
	uint16_t	id_count;
	uint16_t	version_major;
	uint16_t	version_minor;
	uint64_t	root_inode;
	uint64_t	bytes_used;
	uint64_t	id_table;
	uint64_t	xattr_table;
	uint64_t	inode_table;
	uint64_t	dir_table;
	uint64_t	frag_table;
	uint64_t	export_table;
} __attribute__((packed));

#define SQUASHFS_COMP_OPT_FLAG        (1<<10)
#define SQUASHFS_EXTRA_INFO_FLAG      (1<<12)

#define SQUASHFS_COMPRESSED_BIT       (1<<15)
#define SQUASHFS_METADATA_BLOCK_MAX   8192

#define SQUASHFS_EXTRA_INFO_TAG_END   0
#define SQUASHFS_EXTRA_INFO_TAG_LABEL 1
#define SQUASHFS_EXTRA_INFO_TAG_UUID  2

static const uint8_t *get_metadata_block(blkid_probe pr, uint64_t *pofs, uint16_t *pmetablock_len)
{
	const uint8_t *buf = blkid_probe_get_buffer(pr, *pofs, 2);
	if (!buf) return NULL;
	uint16_t metablock_len = (buf[1]<<8) | buf[0];
	if (!(metablock_len & SQUASHFS_COMPRESSED_BIT)) {
		/* a compressed metadata block is not valid here */
		return NULL;
	}
	metablock_len &= ~SQUASHFS_COMPRESSED_BIT;
	if (metablock_len > SQUASHFS_METADATA_BLOCK_MAX) {
		return NULL;
	}
	buf = blkid_probe_get_buffer(pr, *pofs + 2, metablock_len);
	if (!buf) return NULL;
	*pmetablock_len = metablock_len;
	*pofs += 2 + metablock_len;
	return buf;
}

static void probe_extra_info(blkid_probe pr, uint16_t flags)
{
	uint64_t ofs = sizeof(struct sqsh_super_block);
	uint16_t metablock_len;
	const uint8_t *buf;

	/* comp_opts, when present, comes right after the superblock */
	if (flags & SQUASHFS_COMP_OPT_FLAG) {
		buf = get_metadata_block(pr, &ofs, &metablock_len);
		if (!buf) return;
	}

	/* extra_info comes next */
	buf = get_metadata_block(pr, &ofs, &metablock_len);
	if (!buf) return;

	const uint8_t *buf_end = buf + metablock_len;
	while (buf < buf_end) {
		unsigned char type = *buf++;
		if (type == SQUASHFS_EXTRA_INFO_TAG_END || buf >= buf_end)
			return;
		unsigned char len = *buf++;
		if (buf + len > buf_end) return;
		if (type == SQUASHFS_EXTRA_INFO_TAG_LABEL) {
			blkid_probe_set_label(pr, buf, len);
		} else if (type == SQUASHFS_EXTRA_INFO_TAG_UUID) {
			blkid_probe_set_uuid(pr, buf);
		}
		buf += len;
	}
}

static int probe_squashfs(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct sqsh_super_block *sq;
	uint16_t vermaj;
	uint16_t vermin;
	uint16_t flags;

	sq = blkid_probe_get_sb(pr, mag, struct sqsh_super_block);
	if (!sq)
		return errno ? -errno : 1;

	vermaj = le16_to_cpu(sq->version_major);
	vermin = le16_to_cpu(sq->version_minor);
	if (vermaj < 4)
		return 1;

	blkid_probe_sprintf_version(pr, "%u.%u", vermaj, vermin);
	blkid_probe_set_fsblocksize(pr, le32_to_cpu(sq->block_size));
	blkid_probe_set_block_size(pr, le32_to_cpu(sq->block_size));
	blkid_probe_set_fssize(pr, le64_to_cpu(sq->bytes_used));

	flags = le16_to_cpu(sq->flags);
	if (flags & SQUASHFS_EXTRA_INFO_FLAG) {
		probe_extra_info(pr, flags);
	}
	return 0;
}

static int probe_squashfs3(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct sqsh_super_block *sq;
	uint16_t vermaj;
	uint16_t vermin;
	enum BLKID_ENDIANNESS endianness;

	sq = blkid_probe_get_sb(pr, mag, struct sqsh_super_block);
	if (!sq)
		return errno ? -errno : 1;

	if (strcmp(mag->magic, "sqsh") == 0) {
		vermaj = be16_to_cpu(sq->version_major);
		vermin = be16_to_cpu(sq->version_minor);
		endianness = BLKID_ENDIANNESS_BIG;
	} else {
		vermaj = le16_to_cpu(sq->version_major);
		vermin = le16_to_cpu(sq->version_minor);
		endianness = BLKID_ENDIANNESS_LITTLE;
	}

	if (vermaj > 3)
		return 1;

	blkid_probe_sprintf_version(pr, "%u.%u", vermaj, vermin);

	blkid_probe_set_fsblocksize(pr, 1024);
	blkid_probe_set_block_size(pr, 1024);
	blkid_probe_set_fsendianness(pr, endianness);

	return 0;
}

const struct blkid_idinfo squashfs_idinfo =
{
	.name		= "squashfs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_squashfs,
	.magics		=
	{
		{ .magic = "hsqs", .len = 4 },
		{ NULL }
	}
};

const struct blkid_idinfo squashfs3_idinfo =
{
	.name		= "squashfs3",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_squashfs3,
	.magics		=
	{
		{ .magic = "sqsh", .len = 4 }, /* big endian */
		{ .magic = "hsqs", .len = 4 }, /* little endian */
		{ NULL }
	}
};

