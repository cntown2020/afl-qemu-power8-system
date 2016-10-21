#include "qemu/osdep.h"
#include "trace.h"
#include "ui/qemu-spice.h"
#include "sysemu/char.h"
#include <spice.h>
#include <spice/protocol.h>


typedef struct SpiceCharDriver {
    CharDriverState       parent;

    SpiceCharDeviceInstance     sin;
    bool                  active;
    bool                  blocked;
    const uint8_t         *datapos;
    int                   datalen;
    QLIST_ENTRY(SpiceCharDriver) next;
} SpiceCharDriver;

typedef struct SpiceCharSource {
    GSource               source;
    SpiceCharDriver       *scd;
} SpiceCharSource;

static QLIST_HEAD(, SpiceCharDriver) spice_chars =
    QLIST_HEAD_INITIALIZER(spice_chars);

static int vmc_write(SpiceCharDeviceInstance *sin, const uint8_t *buf, int len)
{
    SpiceCharDriver *scd = container_of(sin, SpiceCharDriver, sin);
    CharDriverState *chr = (CharDriverState *)scd;
    ssize_t out = 0;
    ssize_t last_out;
    uint8_t* p = (uint8_t*)buf;

    while (len > 0) {
        int can_write = qemu_chr_be_can_write(chr);
        last_out = MIN(len, can_write);
        if (last_out <= 0) {
            break;
        }
        qemu_chr_be_write(chr, p, last_out);
        out += last_out;
        len -= last_out;
        p += last_out;
    }

    trace_spice_vmc_write(out, len + out);
    return out;
}

static int vmc_read(SpiceCharDeviceInstance *sin, uint8_t *buf, int len)
{
    SpiceCharDriver *scd = container_of(sin, SpiceCharDriver, sin);
    int bytes = MIN(len, scd->datalen);

    if (bytes > 0) {
        memcpy(buf, scd->datapos, bytes);
        scd->datapos += bytes;
        scd->datalen -= bytes;
        assert(scd->datalen >= 0);
    }
    if (scd->datalen == 0) {
        scd->datapos = 0;
        scd->blocked = false;
    }
    trace_spice_vmc_read(bytes, len);
    return bytes;
}

#if SPICE_SERVER_VERSION >= 0x000c02
static void vmc_event(SpiceCharDeviceInstance *sin, uint8_t event)
{
    SpiceCharDriver *scd = container_of(sin, SpiceCharDriver, sin);
    CharDriverState *chr = (CharDriverState *)scd;
    int chr_event;

    switch (event) {
    case SPICE_PORT_EVENT_BREAK:
        chr_event = CHR_EVENT_BREAK;
        break;
    default:
        return;
    }

    trace_spice_vmc_event(chr_event);
    qemu_chr_be_event(chr, chr_event);
}
#endif

static void vmc_state(SpiceCharDeviceInstance *sin, int connected)
{
    SpiceCharDriver *scd = container_of(sin, SpiceCharDriver, sin);
    CharDriverState *chr = (CharDriverState *)scd;

    if ((chr->be_open && connected) ||
        (!chr->be_open && !connected)) {
        return;
    }

    qemu_chr_be_event(chr,
                      connected ? CHR_EVENT_OPENED : CHR_EVENT_CLOSED);
}

static SpiceCharDeviceInterface vmc_interface = {
    .base.type          = SPICE_INTERFACE_CHAR_DEVICE,
    .base.description   = "spice virtual channel char device",
    .base.major_version = SPICE_INTERFACE_CHAR_DEVICE_MAJOR,
    .base.minor_version = SPICE_INTERFACE_CHAR_DEVICE_MINOR,
    .state              = vmc_state,
    .write              = vmc_write,
    .read               = vmc_read,
#if SPICE_SERVER_VERSION >= 0x000c02
    .event              = vmc_event,
#endif
#if SPICE_SERVER_VERSION >= 0x000c06
    .flags              = SPICE_CHAR_DEVICE_NOTIFY_WRITABLE,
#endif
};


static void vmc_register_interface(SpiceCharDriver *scd)
{
    if (scd->active) {
        return;
    }
    scd->sin.base.sif = &vmc_interface.base;
    qemu_spice_add_interface(&scd->sin.base);
    scd->active = true;
    trace_spice_vmc_register_interface(scd);
}

static void vmc_unregister_interface(SpiceCharDriver *scd)
{
    if (!scd->active) {
        return;
    }
    spice_server_remove_interface(&scd->sin.base);
    scd->active = false;
    trace_spice_vmc_unregister_interface(scd);
}

static gboolean spice_char_source_prepare(GSource *source, gint *timeout)
{
    SpiceCharSource *src = (SpiceCharSource *)source;

    *timeout = -1;

    return !src->scd->blocked;
}

static gboolean spice_char_source_check(GSource *source)
{
    SpiceCharSource *src = (SpiceCharSource *)source;

    return !src->scd->blocked;
}

static gboolean spice_char_source_dispatch(GSource *source,
    GSourceFunc callback, gpointer user_data)
{
    GIOFunc func = (GIOFunc)callback;

    return func(NULL, G_IO_OUT, user_data);
}

static GSourceFuncs SpiceCharSourceFuncs = {
    .prepare  = spice_char_source_prepare,
    .check    = spice_char_source_check,
    .dispatch = spice_char_source_dispatch,
};

static GSource *spice_chr_add_watch(CharDriverState *chr, GIOCondition cond)
{
    SpiceCharDriver *scd = (SpiceCharDriver *)chr;
    SpiceCharSource *src;

    assert(cond & G_IO_OUT);

    src = (SpiceCharSource *)g_source_new(&SpiceCharSourceFuncs,
                                          sizeof(SpiceCharSource));
    src->scd = scd;

    return (GSource *)src;
}

static int spice_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    SpiceCharDriver *s = (SpiceCharDriver *)chr;
    int read_bytes;

    assert(s->datalen == 0);
    s->datapos = buf;
    s->datalen = len;
    spice_server_char_device_wakeup(&s->sin);
    read_bytes = len - s->datalen;
    if (read_bytes != len) {
        /* We'll get passed in the unconsumed data with the next call */
        s->datalen = 0;
        s->datapos = NULL;
        s->blocked = true;
    }
    return read_bytes;
}

static void spice_chr_free(struct CharDriverState *chr)
{
    SpiceCharDriver *s = (SpiceCharDriver *)chr;

    vmc_unregister_interface(s);
    QLIST_REMOVE(s, next);

    g_free((char *)s->sin.subtype);
#if SPICE_SERVER_VERSION >= 0x000c02
    g_free((char *)s->sin.portname);
#endif
}

static void spice_vmc_set_fe_open(struct CharDriverState *chr, int fe_open)
{
    SpiceCharDriver *s = (SpiceCharDriver *)chr;
    if (fe_open) {
        vmc_register_interface(s);
    } else {
        vmc_unregister_interface(s);
    }
}

static void spice_port_set_fe_open(struct CharDriverState *chr, int fe_open)
{
#if SPICE_SERVER_VERSION >= 0x000c02
    SpiceCharDriver *s = (SpiceCharDriver *)chr;

    if (fe_open) {
        spice_server_port_event(&s->sin, SPICE_PORT_EVENT_OPENED);
    } else {
        spice_server_port_event(&s->sin, SPICE_PORT_EVENT_CLOSED);
    }
#endif
}

static void print_allowed_subtypes(void)
{
    const char** psubtype;
    int i;

    fprintf(stderr, "allowed names: ");
    for(i=0, psubtype = spice_server_char_device_recognized_subtypes();
        *psubtype != NULL; ++psubtype, ++i) {
        if (i == 0) {
            fprintf(stderr, "%s", *psubtype);
        } else {
            fprintf(stderr, ", %s", *psubtype);
        }
    }
    fprintf(stderr, "\n");
}

static void spice_chr_accept_input(struct CharDriverState *chr)
{
    SpiceCharDriver *s = (SpiceCharDriver *)chr;

    spice_server_char_device_wakeup(&s->sin);
}

static CharDriverState *chr_open(const CharDriver *driver,
                                 const char *subtype,
                                 ChardevCommon *backend,
                                 Error **errp)
{
    CharDriverState *chr;
    SpiceCharDriver *s;

    chr = qemu_chr_alloc(driver, backend, errp);
    if (!chr) {
        return NULL;
    }
    s = (SpiceCharDriver *)chr;
    s->active = false;
    s->sin.subtype = g_strdup(subtype);

    QLIST_INSERT_HEAD(&spice_chars, s, next);

    return chr;
}

static CharDriverState *qemu_chr_open_spice_vmc(const CharDriver *driver,
                                                const char *id,
                                                ChardevBackend *backend,
                                                ChardevReturn *ret,
                                                bool *be_opened,
                                                Error **errp)
{
    ChardevSpiceChannel *spicevmc = backend->u.spicevmc.data;
    const char *type = spicevmc->type;
    const char **psubtype = spice_server_char_device_recognized_subtypes();
    ChardevCommon *common = qapi_ChardevSpiceChannel_base(spicevmc);

    for (; *psubtype != NULL; ++psubtype) {
        if (strcmp(type, *psubtype) == 0) {
            break;
        }
    }
    if (*psubtype == NULL) {
        fprintf(stderr, "spice-qemu-char: unsupported type: %s\n", type);
        print_allowed_subtypes();
        return NULL;
    }

    *be_opened = false;
    return chr_open(driver, type, common, errp);
}

#if SPICE_SERVER_VERSION >= 0x000c02
static CharDriverState *qemu_chr_open_spice_port(const CharDriver *driver,
                                                 const char *id,
                                                 ChardevBackend *backend,
                                                 ChardevReturn *ret,
                                                 bool *be_opened,
                                                 Error **errp)
{
    ChardevSpicePort *spiceport = backend->u.spiceport.data;
    const char *name = spiceport->fqdn;
    ChardevCommon *common = qapi_ChardevSpicePort_base(spiceport);
    CharDriverState *chr;
    SpiceCharDriver *s;

    if (name == NULL) {
        fprintf(stderr, "spice-qemu-char: missing name parameter\n");
        return NULL;
    }

    chr = chr_open(driver, "port", common, errp);
    if (!chr) {
        return NULL;
    }
    *be_opened = false;
    s = (SpiceCharDriver *)chr;
    s->sin.portname = g_strdup(name);

    return chr;
}

void qemu_spice_register_ports(void)
{
    SpiceCharDriver *s;

    QLIST_FOREACH(s, &spice_chars, next) {
        if (s->sin.portname == NULL) {
            continue;
        }
        vmc_register_interface(s);
    }
}
#endif

static void qemu_chr_parse_spice_vmc(QemuOpts *opts, ChardevBackend *backend,
                                     Error **errp)
{
    const char *name = qemu_opt_get(opts, "name");
    ChardevSpiceChannel *spicevmc;

    if (name == NULL) {
        error_setg(errp, "chardev: spice channel: no name given");
        return;
    }
    spicevmc = backend->u.spicevmc.data = g_new0(ChardevSpiceChannel, 1);
    qemu_chr_parse_common(opts, qapi_ChardevSpiceChannel_base(spicevmc));
    spicevmc->type = g_strdup(name);
}

static void qemu_chr_parse_spice_port(QemuOpts *opts, ChardevBackend *backend,
                                      Error **errp)
{
    const char *name = qemu_opt_get(opts, "name");
    ChardevSpicePort *spiceport;

    if (name == NULL) {
        error_setg(errp, "chardev: spice port: no name given");
        return;
    }
    spiceport = backend->u.spiceport.data = g_new0(ChardevSpicePort, 1);
    qemu_chr_parse_common(opts, qapi_ChardevSpicePort_base(spiceport));
    spiceport->fqdn = g_strdup(name);
}

static void register_types(void)
{
    static const CharDriver vmc_driver = {
        .instance_size = sizeof(SpiceCharDriver),
        .kind = CHARDEV_BACKEND_KIND_SPICEVMC,
        .parse = qemu_chr_parse_spice_vmc,
        .create = qemu_chr_open_spice_vmc,
        .chr_write = spice_chr_write,
        .chr_add_watch = spice_chr_add_watch,
        .chr_set_fe_open = spice_vmc_set_fe_open,
        .chr_accept_input = spice_chr_accept_input,
        .chr_free = spice_chr_free,
    };
    static const CharDriver port_driver = {
        .instance_size = sizeof(SpiceCharDriver),
        .kind = CHARDEV_BACKEND_KIND_SPICEPORT,
        .parse = qemu_chr_parse_spice_port,
        .create = qemu_chr_open_spice_port,
        .chr_write = spice_chr_write,
        .chr_add_watch = spice_chr_add_watch,
        .chr_set_fe_open = spice_port_set_fe_open,
        .chr_accept_input = spice_chr_accept_input,
        .chr_free = spice_chr_free,
    };
    register_char_driver(&vmc_driver);
    register_char_driver(&port_driver);
}

type_init(register_types);
