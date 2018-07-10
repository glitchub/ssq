A secure squashfs (ssq) image is a regular squashfs image appended with a table
of SHA256s, one for each 4K block of the original image. This increases the
overall image size by about 0.8%. 

The 'mkssq' program is used to generate or verify the ssq image and report the
64-digit signature needed to mount it.

If '-o ssq=<mount signature>' option is used when mounting the ssq image then
the kernel will load the appended table into memory and verify that its SHA256
matches the mount signature. If not then mount fails.

Thereafter, when a 4K block belonging to the image is read from backing store,
the kernel verifies that the SHA256 of the block matches the associated entry
from the table in memory. If not then a read error occurs (or the kernel will
panic if SQUASHFS_SSQ_PANIC is enabled).

Note if the 'ssq=' option is not provided then an ssq image will mount as a
normal insecure squashfs.

Similarly, if SQUASHFS_SSQ isn't enabled then squashfs will ignore the
'ssq=' option and ssq images will mount as a normal squashfs.

This repo contains the following directories:

    squashfs - linux 4.1.20 source patched for secure squashfs. All changes are
    wrapped with "CONFIG_SQUASHFS_SSQ".

    diffs - diffs against the same 4.1.20 source.

    util - directory containing the mkssq program

In order to build SQUASHFS_SSQ you must also enable CRYPTO_SHA256 and
SQUASHFS_4K_DEVBLK_SIZE.
