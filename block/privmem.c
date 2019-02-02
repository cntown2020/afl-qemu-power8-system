/*
 * non-persistent / private memory block driver, COW on fork
 *
 * Authors:
 *  Ryan Hileman <lunixbochs@gmail.com>
 *
 * Copyright (C) 2016 Ryan Hileman
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <sys/mman.h>

#include "qemu/osdep.h"

#define ZLIB_CONST
#include <zlib.h>

#include "block/block_int.h"
#include "block/qdict.h"
#include "sysemu/block-backend.h"
#include "qemu/module.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qapi/qapi-events-block-core.h"
#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qstring.h"
#include "trace.h"
#include "qemu/option_int.h"
#include "qemu/cutils.h"
#include "qemu/bswap.h"
#include "qapi/qobject-input-visitor.h"
#include "qapi/qapi-visit-block-core.h"
#include "crypto.h"
#include "block/thread-pool.h"




#include "block/block_int.h"

typedef struct {
    int fd;
    char *buf;
    size_t size;
} BDRVCOWState;

static QemuOptsList runtime_opts = {
    .name = "privmem",
    .head = QTAILQ_HEAD_INITIALIZER(runtime_opts.head),
    .desc = {
        {
            .name = "filename",
            .type = QEMU_OPT_STRING,
            .help = "",
        },
        { /* end of list */ }
    },
};

static int privmem_file_open(BlockDriverState *bs, QDict *options, int flags,
                          Error **errp)
{
    QemuOpts *opts;
    BDRVCOWState *s = bs->opaque;
    const char *filename, *p;
    struct stat sb;
    int ret = 0;

    opts = qemu_opts_create(&runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &error_abort);
    filename = qemu_opt_get(opts, "filename");
    if (error_abort) {
        error_propagate(errp, error_abort);
        ret = -EINVAL;
        goto fail;
    }

    /* strip "privmem:". XXX whats the proper way to handle this? */
    p = strchr(filename, ':');
    if(p)
        filename = p + 1;

    s->fd = qemu_open(filename, O_RDONLY);
    if (fstat(s->fd, &sb) == -1 || !S_ISREG(sb.st_mode)) {
        perror(filename);
        ret = -EINVAL;
        goto fail;
    }
    s->size = sb.st_size;
    s->buf = mmap(0, sb.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_NORESERVE, s->fd, 0);
    if (s->buf == MAP_FAILED) {
        perror("mmap");
        ret = -EINVAL;
        goto fail;
    }

fail:
    qemu_opts_del(opts);
    return ret;
}

static void privmem_close(BlockDriverState *bs)
{
    BDRVCOWState *s = bs->opaque;
    munmap(s->buf, s->size);
    close(s->fd);
}

static int64_t privmem_getlength(BlockDriverState *bs)
{
    BDRVCOWState *s = bs->opaque;
    return s->size;
}

/* no bounds checking. Possible for guest to do a lot of reading/writing it shouldn't */
static coroutine_fn int privmem_read(BlockDriverState *bs, uint64_t offset,
                                      uint64_t bytes, QEMUIOVector *qiov,
                                      int flags)
{
    BDRVCOWState *s = bs->opaque;
    return qemu_iovec_from_buf(qiov,0,s->buf+offset,bytes);
}

static coroutine_fn int privmem_write(BlockDriverState *bs, uint64_t offset,
                                      uint64_t bytes, QEMUIOVector *qiov,
                                      int flags)
{
    BDRVCOWState *s = bs->opaque;
    return qemu_iovec_to_buf(qiov,0,s->buf+offset, bytes);
}

static BlockDriver bdrv_privmem = {
    .format_name            = "privmem",
    .protocol_name          = "privmem",
    .instance_size          = sizeof(BDRVCOWState),

    .bdrv_file_open         = privmem_file_open,
    .bdrv_close             = privmem_close,
    .bdrv_getlength         = privmem_getlength,

    .bdrv_co_preadv          = privmem_read,
    .bdrv_co_pwritev         = privmem_write,
};

static void bdrv_privmem_init(void)
{
    bdrv_register(&bdrv_privmem);
}

block_init(bdrv_privmem_init);
