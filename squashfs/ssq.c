// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation; either version 2, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, 51 Franklin
// Street, Fifth Floor, Boston, MA 02110-1301, USA.

// A secure squashfs image (ssq) is just a regular squashfs with an appended
// table of binary SHA256's, one for each 4K block. The mkssq tool is used to
// append the table and return the signature that can be used to mount the ssq
// image.
//
// If mount option '-ossq=<signature>' is specified, then the table of appended
// SHA256s are loaded into memory and verified against the supplied signature.
// If incorrect, then the mount fails outright.
//
// Otherwise the mount succeeds. As individual squashfs blocks are read from
// the backing store their SHA256 is verified against the corresponding SHA256
// in the table. If an invalid block is dicovered it either means that the
// backing store is corrupted or the block has been intentionally altered. The
// kernel will optionally panic, otherwise return a read error.
//
// Note if -ossq=<signature> is not provided then the appended table is ignored
// and the ssq image will be mount as an normal insecure squashfs.

#include <linux/fs.h>
#include "squashfs_fs_sb.h"
#include "squashfs.h"

#include <linux/vmalloc.h>
#include <linux/buffer_head.h>

// Squashfs must be configured for 4K blocks
#ifndef CONFIG_SQUASHFS_4K_DEVBLK_SIZE
#error "Requires CONFIG_SQUASHFS_4K_DEVBLK_SIZE"
#endif

// Bytes in a read block
#define BLKSIZE 4096

// And SHA256 must be enabled
#ifndef CONFIG_CRYPTO_SHA256
#error "Requires CONFIG_CRYPTO_SHA256"
#endif

// Bytes in a binary sha256
#define SHASIZE 32

// Kernel version-specific sha256 routines: initsha, upsha, getsha, freesha
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,6,0)
#include <linux/scatterlist.h>
#include <linux/crypto.h>
static struct hash_desc *initsha(void)
{
    struct hash_desc *h=NULL;
    struct crypto_hash *tfm = crypto_alloc_hash("sha256", 0, 0);
    if (IS_ERR(tfm)) { tfm=NULL; goto initx; }
    if (!(h=vmalloc(sizeof(struct hash_desc)))) goto initx;
    h->tfm=tfm;
    h->flags=0;
    if (!crypto_hash_init(h)) return h;
  initx:
    ERROR("ssq initsha failed\n");
    if (h) vfree(h);
    if (tfm) crypto_free_hash(tfm);
    return NULL;
}

static int upsha(struct hash_desc *h, void *data, int size)
{
    struct scatterlist sg;
    sg_init_one(&sg, data, size);
    if (!crypto_hash_update(h, &sg, size)) return 0;
    ERROR("ssq upsha failed\n");
    return -EFAULT;
}

static int getsha(struct hash_desc *h, void *result)
{
    if (!crypto_hash_final(h, result)) return 0;
    ERROR("ssq getsha failed\n");
    return -EINVAL;
}

static void freesha(struct hash_desc **h)
{
    if (!*h) return;
    crypto_free_hash((*h)->tfm);
    vfree(*h);
    *h=NULL;
}
#else
#include "crypto/hash.h"
static struct shash_desc *initsha(void)
{
    struct shash_desc *h=NULL;
    struct crypto_shash *tfm = crypto_alloc_shash("sha256", 0, 0);
    if (!tfm) goto initx;
    if (!(h=vmalloc(sizeof(struct shash_desc) + crypto_shash_descsize(tfm)))) goto initx;
    h->tfm=tfm;
    h->flags=0;
    if (!crypto_shash_init(h)) return h;
  initx:
    ERROR("ssh initsha failed\n");
    if (h) vfree(h);
    if (tfm) crypto_free_shash(tfm);
    return NULL;
}

static int upsha(struct shash_desc *h, void *data, int size)
{
    if (!*h) return -EINVAL;
    if (!crypto_shash_update(h, data, size)) return 0;
    ERROR("ssh upsha failed\n");
    return -EFAULT;
}

static int getsha(struct shash_desc *h, void *sha)
{
    if (!crypto_shash_final(h, sha)) return 0;
    ERROR("ssh getsha failed\n");
    return -EFAULT;
}

static void freesha(struct shash_desc **h)
{
    if (!*h) return;
    crypto_free_shash((*h)->tfm);
    vfree(*h);
    *h=NULL;
}
#endif

// Free the squashfs ssq sha table
void ssq_free(struct super_block *sb)
{
    struct squashfs_sb_info *msblk = sb->s_fs_info;
    vfree(msblk->ssq_shas); // NULL ok
}

// Search for ssq= mount option. If not found then return 1.  Otherwise read
// the appended SHA256 table into memory, verify the signature, and return 1.
// On any error, return 0 to abort the mount.
// This must be called from fill_super() prior to reading any squashfs metadata
// other than the superblock.
int ssq_fill_super(struct super_block *sb, char *data, int silent)
{
    char *opt;
    (void) silent;
    void *hd=NULL; // hash descriptor

    while ((opt = strsep(&data,",")) != NULL) if (!strncmp(opt, "ssq=", 4))
    {
        struct buffer_head *bh;
        uint8_t sha256[SHASIZE];
        char actual[(SHASIZE*2)+1];
        int blocks, block, bytes;

        char *expected = &opt[4];
        struct squashfs_sb_info *msblk=sb->s_fs_info;

        pr_info("SQUASHFS: mounting ssq with signature %s...\n", expected);

        // Max image 1GB to avoid excessive vmalloc (and uint64_t)
        if (msblk->bytes_used > 1024*1024*1024LL)
        {
            ERROR("ssq base image cannot exceed 1GB\n");
            goto fail;
        }

        // Determine total number of blocks.
        blocks = (msblk->bytes_used+(BLKSIZE-1)) / BLKSIZE;

        // Allocate space to contain that many SHA256's, note could be up to 8MB!
        if (!(msblk->ssq_shas = vmalloc(blocks*SHASIZE)))
        {
            ERROR("ssq out of memory\n");
            goto fail;
        }

        // Prepare for the signature, e.g. sha256 of block 0 plus appended table
        if (!(hd=initsha())) goto fail;
        if (!(bh = sb_bread(sb,0)))
        {
            ERROR("ssq unable to read block 0\n");
            goto fail;
        }

        if (upsha(hd, bh->b_data, BLKSIZE) < 0)) goto fail; 

        put_bh(bh); // leave block 0 in memory

        // Read blocks of appended SHAs to memory, starting from nominal end of image.
        for (block=0, bytes=blocks*SHASIZE; bytes > 0; block++, bytes-=BLKSIZE)
        {
            int size = (bytes > BLKSIZE) ? BLKSIZE : bytes;
            if (!(bh=sb_bread(sb, blocks+block)))
            {
                ERROR("ssq unable to read block %u\n", blocks+block);
                goto fail;
            }
            memcpy(msblk->ssq_shas+(block*BLKSIZE), bh->b_data, size);  // appended to table
            if (upsha(hd, bh->b_data, size)) goto fail;                // update the signature
            brelse(bh);
        }

        // Verify the signature
        getsha(hd, sha256);
        freesha(&hd); 
        sprintf(actual, "%*phN", SHASIZE, sha256);  // convert sha256 to hex
        if (strcasecmp(actual, expected))           // matches given string?
        {
            ERROR("ssq actual signature is %s\n", actual);
            goto fail;
        }
        break;
    }
    return 1;

  fail:
    ssq_free(sb);
    freesha(&hd);
    return 0;
}

// Return 1 if block at bh is valid, or 0 if invalid.
#define CHECKED (void *)0x53535121 // SSQ!
int ssq_test_bh(struct super_block *sb, struct buffer_head *bh)
{
    struct squashfs_sb_info *msblk = sb->s_fs_info;
    uint8_t sha256[SHASIZE];
    void *hd; // hash descriptor

    if (!msblk->ssq_shas) return 1;             // Success if ssq not in use
    if (bh->b_private == CHECKED) return 1;     // Success if block has already been checked

    // Generate sha256
    if (!(hd=initsha()) || upsha(hd, bh->b_data, BLKSIZE) || getsha(hd, sha256)) goto readerr;
    freesha(&hd);

    // Verify against the corresponding entry in the table
    if (memcmp(sha256, msblk->ssq_shas+(bh->b_blocknr*SHASIZE), SHASIZE))
    {
        char name[BDEVNAME_SIZE];
        bdevname(sb->s_bdev,name);
        ERROR("ssq block %lld on %s is invalid, expected=%*phN, actual=%*phN\n",
            bh->b_blocknr, bdevname(sb->s_bdev,name), SHASIZE, (void *)msblk->ssq_shas+(bh->b_blocknr*SHASIZE), SHASIZE, sha256);

     readerr:
#ifndef CONFIG_SQUASHFS_SSQ_PANIC
        panic("SQUASHFS: ssq read verification failed\n"); // b-bye!
#endif            
        return 0;               
    }
 
    // OK, we're good. Use the buffer head's (void *)b_private as a flag to
    // remember that we did this. If the buffer is subsequently flushed then a
    // new bh will be created with b_private==NULL and it will be re-checked.
    bh->b_private = CHECKED;
    return 1;
}
