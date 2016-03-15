/*
 * Inter-VM Shared Memory PCI device.
 *
 * Author:
 *      Cam Macdonell <cam@cs.ualberta.ca>
 *
 * Based On: cirrus_vga.c
 *          Copyright (c) 2004 Fabrice Bellard
 *          Copyright (c) 2004 Makoto Suzuki (suzu)
 *
 *      and rtl8139.c
 *          Copyright (c) 2006 Igor Kovalenko
 *
 * This code is licensed under the GNU GPL v2.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */
#include "qemu/osdep.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qom/object_interfaces.h"
#include "sysemu/char.h"
#include "sysemu/hostmem.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"

#include "hw/misc/ivshmem.h"

#include <sys/mman.h>

#define PCI_VENDOR_ID_IVSHMEM   PCI_VENDOR_ID_REDHAT_QUMRANET
#define PCI_DEVICE_ID_IVSHMEM   0x1110

#define IVSHMEM_MAX_PEERS UINT16_MAX
#define IVSHMEM_IOEVENTFD   0
#define IVSHMEM_MSI     1

#define IVSHMEM_REG_BAR_SIZE 0x100

#define IVSHMEM_DEBUG 0
#define IVSHMEM_DPRINTF(fmt, ...)                       \
    do {                                                \
        if (IVSHMEM_DEBUG) {                            \
            printf("IVSHMEM: " fmt, ## __VA_ARGS__);    \
        }                                               \
    } while (0)

#define TYPE_IVSHMEM "ivshmem"
#define IVSHMEM(obj) \
    OBJECT_CHECK(IVShmemState, (obj), TYPE_IVSHMEM)

typedef struct Peer {
    int nb_eventfds;
    EventNotifier *eventfds;
} Peer;

typedef struct MSIVector {
    PCIDevice *pdev;
    int virq;
} MSIVector;

typedef struct IVShmemState {
    /*< private >*/
    PCIDevice parent_obj;
    /*< public >*/

    HostMemoryBackend *hostmem;
    uint32_t intrmask;
    uint32_t intrstatus;

    CharDriverState *server_chr;
    MemoryRegion ivshmem_mmio;

    MemoryRegion *ivshmem_bar2; /* BAR 2 (shared memory) */
    MemoryRegion server_bar2;   /* used with server_chr */
    size_t ivshmem_size; /* size of shared memory region */
    uint32_t ivshmem_64bit;

    Peer *peers;
    int nb_peers;               /* space in @peers[] */

    int vm_id;
    uint32_t vectors;
    uint32_t features;
    MSIVector *msi_vectors;
    uint64_t msg_buf;           /* buffer for receiving server messages */
    int msg_buffered_bytes;     /* #bytes in @msg_buf */

    OnOffAuto master;
    Error *migration_blocker;

    char * shmobj;
    char * sizearg;
    char * role;
} IVShmemState;

/* registers for the Inter-VM shared memory device */
enum ivshmem_registers {
    INTRMASK = 0,
    INTRSTATUS = 4,
    IVPOSITION = 8,
    DOORBELL = 12,
};

static inline uint32_t ivshmem_has_feature(IVShmemState *ivs,
                                                    unsigned int feature) {
    return (ivs->features & (1 << feature));
}

static inline bool ivshmem_is_master(IVShmemState *s)
{
    assert(s->master != ON_OFF_AUTO_AUTO);
    return s->master == ON_OFF_AUTO_ON;
}

static void ivshmem_update_irq(IVShmemState *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    uint32_t isr = s->intrstatus & s->intrmask;

    /* No INTx with msi=on, whether the guest enabled MSI-X or not */
    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        return;
    }

    /* don't print ISR resets */
    if (isr) {
        IVSHMEM_DPRINTF("Set IRQ to %d (%04x %04x)\n",
                        isr ? 1 : 0, s->intrstatus, s->intrmask);
    }

    pci_set_irq(d, isr != 0);
}

static void ivshmem_IntrMask_write(IVShmemState *s, uint32_t val)
{
    IVSHMEM_DPRINTF("IntrMask write(w) val = 0x%04x\n", val);

    s->intrmask = val;
    ivshmem_update_irq(s);
}

static uint32_t ivshmem_IntrMask_read(IVShmemState *s)
{
    uint32_t ret = s->intrmask;

    IVSHMEM_DPRINTF("intrmask read(w) val = 0x%04x\n", ret);
    return ret;
}

static void ivshmem_IntrStatus_write(IVShmemState *s, uint32_t val)
{
    IVSHMEM_DPRINTF("IntrStatus write(w) val = 0x%04x\n", val);

    s->intrstatus = val;
    ivshmem_update_irq(s);
}

static uint32_t ivshmem_IntrStatus_read(IVShmemState *s)
{
    uint32_t ret = s->intrstatus;

    /* reading ISR clears all interrupts */
    s->intrstatus = 0;
    ivshmem_update_irq(s);
    return ret;
}

static void ivshmem_io_write(void *opaque, hwaddr addr,
                             uint64_t val, unsigned size)
{
    IVShmemState *s = opaque;

    uint16_t dest = val >> 16;
    uint16_t vector = val & 0xff;

    addr &= 0xfc;

    IVSHMEM_DPRINTF("writing to addr " TARGET_FMT_plx "\n", addr);
    switch (addr)
    {
        case INTRMASK:
            ivshmem_IntrMask_write(s, val);
            break;

        case INTRSTATUS:
            ivshmem_IntrStatus_write(s, val);
            break;

        case DOORBELL:
            /* check that dest VM ID is reasonable */
            if (dest >= s->nb_peers) {
                IVSHMEM_DPRINTF("Invalid destination VM ID (%d)\n", dest);
                break;
            }

            /* check doorbell range */
            if (vector < s->peers[dest].nb_eventfds) {
                IVSHMEM_DPRINTF("Notifying VM %d on vector %d\n", dest, vector);
                event_notifier_set(&s->peers[dest].eventfds[vector]);
            } else {
                IVSHMEM_DPRINTF("Invalid destination vector %d on VM %d\n",
                                vector, dest);
            }
            break;
        default:
            IVSHMEM_DPRINTF("Unhandled write " TARGET_FMT_plx "\n", addr);
    }
}

static uint64_t ivshmem_io_read(void *opaque, hwaddr addr,
                                unsigned size)
{

    IVShmemState *s = opaque;
    uint32_t ret;

    switch (addr)
    {
        case INTRMASK:
            ret = ivshmem_IntrMask_read(s);
            break;

        case INTRSTATUS:
            ret = ivshmem_IntrStatus_read(s);
            break;

        case IVPOSITION:
            ret = s->vm_id;
            break;

        default:
            IVSHMEM_DPRINTF("why are we reading " TARGET_FMT_plx "\n", addr);
            ret = 0;
    }

    return ret;
}

static const MemoryRegionOps ivshmem_mmio_ops = {
    .read = ivshmem_io_read,
    .write = ivshmem_io_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void ivshmem_vector_notify(void *opaque)
{
    MSIVector *entry = opaque;
    PCIDevice *pdev = entry->pdev;
    IVShmemState *s = IVSHMEM(pdev);
    int vector = entry - s->msi_vectors;
    EventNotifier *n = &s->peers[s->vm_id].eventfds[vector];

    if (!event_notifier_test_and_clear(n)) {
        return;
    }

    IVSHMEM_DPRINTF("interrupt on vector %p %d\n", pdev, vector);
    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        if (msix_enabled(pdev)) {
            msix_notify(pdev, vector);
        }
    } else {
        ivshmem_IntrStatus_write(s, 1);
    }
}

static int ivshmem_vector_unmask(PCIDevice *dev, unsigned vector,
                                 MSIMessage msg)
{
    IVShmemState *s = IVSHMEM(dev);
    EventNotifier *n = &s->peers[s->vm_id].eventfds[vector];
    MSIVector *v = &s->msi_vectors[vector];
    int ret;

    IVSHMEM_DPRINTF("vector unmask %p %d\n", dev, vector);

    ret = kvm_irqchip_update_msi_route(kvm_state, v->virq, msg, dev);
    if (ret < 0) {
        return ret;
    }

    return kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, n, NULL, v->virq);
}

static void ivshmem_vector_mask(PCIDevice *dev, unsigned vector)
{
    IVShmemState *s = IVSHMEM(dev);
    EventNotifier *n = &s->peers[s->vm_id].eventfds[vector];
    int ret;

    IVSHMEM_DPRINTF("vector mask %p %d\n", dev, vector);

    ret = kvm_irqchip_remove_irqfd_notifier_gsi(kvm_state, n,
                                                s->msi_vectors[vector].virq);
    if (ret != 0) {
        error_report("remove_irqfd_notifier_gsi failed");
    }
}

static void ivshmem_vector_poll(PCIDevice *dev,
                                unsigned int vector_start,
                                unsigned int vector_end)
{
    IVShmemState *s = IVSHMEM(dev);
    unsigned int vector;

    IVSHMEM_DPRINTF("vector poll %p %d-%d\n", dev, vector_start, vector_end);

    vector_end = MIN(vector_end, s->vectors);

    for (vector = vector_start; vector < vector_end; vector++) {
        EventNotifier *notifier = &s->peers[s->vm_id].eventfds[vector];

        if (!msix_is_masked(dev, vector)) {
            continue;
        }

        if (event_notifier_test_and_clear(notifier)) {
            msix_set_pending(dev, vector);
        }
    }
}

static void watch_vector_notifier(IVShmemState *s, EventNotifier *n,
                                 int vector)
{
    int eventfd = event_notifier_get_fd(n);

    assert(!s->msi_vectors[vector].pdev);
    s->msi_vectors[vector].pdev = PCI_DEVICE(s);

    qemu_set_fd_handler(eventfd, ivshmem_vector_notify,
                        NULL, &s->msi_vectors[vector]);
}

static void ivshmem_add_eventfd(IVShmemState *s, int posn, int i)
{
    memory_region_add_eventfd(&s->ivshmem_mmio,
                              DOORBELL,
                              4,
                              true,
                              (posn << 16) | i,
                              &s->peers[posn].eventfds[i]);
}

static void ivshmem_del_eventfd(IVShmemState *s, int posn, int i)
{
    memory_region_del_eventfd(&s->ivshmem_mmio,
                              DOORBELL,
                              4,
                              true,
                              (posn << 16) | i,
                              &s->peers[posn].eventfds[i]);
}

static void close_peer_eventfds(IVShmemState *s, int posn)
{
    int i, n;

    assert(posn >= 0 && posn < s->nb_peers);
    n = s->peers[posn].nb_eventfds;

    if (ivshmem_has_feature(s, IVSHMEM_IOEVENTFD)) {
        memory_region_transaction_begin();
        for (i = 0; i < n; i++) {
            ivshmem_del_eventfd(s, posn, i);
        }
        memory_region_transaction_commit();
    }

    for (i = 0; i < n; i++) {
        event_notifier_cleanup(&s->peers[posn].eventfds[i]);
    }

    g_free(s->peers[posn].eventfds);
    s->peers[posn].nb_eventfds = 0;
}

static void resize_peers(IVShmemState *s, int nb_peers)
{
    int old_nb_peers = s->nb_peers;
    int i;

    assert(nb_peers > old_nb_peers);
    IVSHMEM_DPRINTF("bumping storage to %d peers\n", nb_peers);

    s->peers = g_realloc(s->peers, nb_peers * sizeof(Peer));
    s->nb_peers = nb_peers;

    for (i = old_nb_peers; i < nb_peers; i++) {
        s->peers[i].eventfds = g_new0(EventNotifier, s->vectors);
        s->peers[i].nb_eventfds = 0;
    }
}

static void ivshmem_add_kvm_msi_virq(IVShmemState *s, int vector,
                                     Error **errp)
{
    PCIDevice *pdev = PCI_DEVICE(s);
    MSIMessage msg = msix_get_message(pdev, vector);
    int ret;

    IVSHMEM_DPRINTF("ivshmem_add_kvm_msi_virq vector:%d\n", vector);
    assert(!s->msi_vectors[vector].pdev);

    ret = kvm_irqchip_add_msi_route(kvm_state, msg, pdev);
    if (ret < 0) {
        error_setg(errp, "kvm_irqchip_add_msi_route failed");
        return;
    }

    s->msi_vectors[vector].virq = ret;
    s->msi_vectors[vector].pdev = pdev;
}

static void setup_interrupt(IVShmemState *s, int vector, Error **errp)
{
    EventNotifier *n = &s->peers[s->vm_id].eventfds[vector];
    bool with_irqfd = kvm_msi_via_irqfd_enabled() &&
        ivshmem_has_feature(s, IVSHMEM_MSI);
    PCIDevice *pdev = PCI_DEVICE(s);
    Error *err = NULL;

    IVSHMEM_DPRINTF("setting up interrupt for vector: %d\n", vector);

    if (!with_irqfd) {
        IVSHMEM_DPRINTF("with eventfd\n");
        watch_vector_notifier(s, n, vector);
    } else if (msix_enabled(pdev)) {
        IVSHMEM_DPRINTF("with irqfd\n");
        ivshmem_add_kvm_msi_virq(s, vector, &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        if (!msix_is_masked(pdev, vector)) {
            kvm_irqchip_add_irqfd_notifier_gsi(kvm_state, n, NULL,
                                               s->msi_vectors[vector].virq);
            /* TODO handle error */
        }
    } else {
        /* it will be delayed until msix is enabled, in write_config */
        IVSHMEM_DPRINTF("with irqfd, delayed until msix enabled\n");
    }
}

static void process_msg_shmem(IVShmemState *s, int fd, Error **errp)
{
    struct stat buf;
    void *ptr;

    if (s->ivshmem_bar2) {
        error_setg(errp, "server sent unexpected shared memory message");
        close(fd);
        return;
    }

    if (fstat(fd, &buf) < 0) {
        error_setg_errno(errp, errno,
            "can't determine size of shared memory sent by server");
        close(fd);
        return;
    }

    if (s->ivshmem_size > buf.st_size) {
        error_setg(errp, "server sent only %zd bytes of shared memory",
                   (size_t)buf.st_size);
        close(fd);
        return;
    }

    /* mmap the region and map into the BAR2 */
    ptr = mmap(0, s->ivshmem_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        error_setg_errno(errp, errno, "Failed to mmap shared memory");
        close(fd);
        return;
    }
    memory_region_init_ram_ptr(&s->server_bar2, OBJECT(s),
                               "ivshmem.bar2", s->ivshmem_size, ptr);
    qemu_set_ram_fd(memory_region_get_ram_addr(&s->server_bar2), fd);
    s->ivshmem_bar2 = &s->server_bar2;
}

static void process_msg_disconnect(IVShmemState *s, uint16_t posn,
                                   Error **errp)
{
    IVSHMEM_DPRINTF("posn %d has gone away\n", posn);
    if (posn >= s->nb_peers || posn == s->vm_id) {
        error_setg(errp, "invalid peer %d", posn);
        return;
    }
    close_peer_eventfds(s, posn);
}

static void process_msg_connect(IVShmemState *s, uint16_t posn, int fd,
                                Error **errp)
{
    Peer *peer = &s->peers[posn];
    int vector;

    /*
     * The N-th connect message for this peer comes with the file
     * descriptor for vector N-1.  Count messages to find the vector.
     */
    if (peer->nb_eventfds >= s->vectors) {
        error_setg(errp, "Too many eventfd received, device has %d vectors",
                   s->vectors);
        close(fd);
        return;
    }
    vector = peer->nb_eventfds++;

    IVSHMEM_DPRINTF("eventfds[%d][%d] = %d\n", posn, vector, fd);
    event_notifier_init_fd(&peer->eventfds[vector], fd);
    fcntl_setfl(fd, O_NONBLOCK); /* msix/irqfd poll non block */

    if (posn == s->vm_id) {
        setup_interrupt(s, vector, errp);
        /* TODO do we need to handle the error? */
    }

    if (ivshmem_has_feature(s, IVSHMEM_IOEVENTFD)) {
        ivshmem_add_eventfd(s, posn, vector);
    }
}

static void process_msg(IVShmemState *s, int64_t msg, int fd, Error **errp)
{
    IVSHMEM_DPRINTF("posn is %" PRId64 ", fd is %d\n", msg, fd);

    if (msg < -1 || msg > IVSHMEM_MAX_PEERS) {
        error_setg(errp, "server sent invalid message %" PRId64, msg);
        close(fd);
        return;
    }

    if (msg == -1) {
        process_msg_shmem(s, fd, errp);
        return;
    }

    if (msg >= s->nb_peers) {
        resize_peers(s, msg + 1);
    }

    if (fd >= 0) {
        process_msg_connect(s, msg, fd, errp);
    } else {
        process_msg_disconnect(s, msg, errp);
    }
}

static int ivshmem_can_receive(void *opaque)
{
    IVShmemState *s = opaque;

    assert(s->msg_buffered_bytes < sizeof(s->msg_buf));
    return sizeof(s->msg_buf) - s->msg_buffered_bytes;
}

static void ivshmem_read(void *opaque, const uint8_t *buf, int size)
{
    IVShmemState *s = opaque;
    Error *err = NULL;
    int fd;
    int64_t msg;

    assert(size >= 0 && s->msg_buffered_bytes + size <= sizeof(s->msg_buf));
    memcpy((unsigned char *)&s->msg_buf + s->msg_buffered_bytes, buf, size);
    s->msg_buffered_bytes += size;
    if (s->msg_buffered_bytes < sizeof(s->msg_buf)) {
        return;
    }
    msg = le64_to_cpu(s->msg_buf);
    s->msg_buffered_bytes = 0;

    fd = qemu_chr_fe_get_msgfd(s->server_chr);
    IVSHMEM_DPRINTF("posn is %" PRId64 ", fd is %d\n", msg, fd);

    process_msg(s, msg, fd, &err);
    if (err) {
        error_report_err(err);
    }
}

static int64_t ivshmem_recv_msg(IVShmemState *s, int *pfd, Error **errp)
{
    int64_t msg;
    int n, ret;

    n = 0;
    do {
        ret = qemu_chr_fe_read_all(s->server_chr, (uint8_t *)&msg + n,
                                 sizeof(msg) - n);
        if (ret < 0 && ret != -EINTR) {
            error_setg_errno(errp, -ret, "read from server failed");
            return INT64_MIN;
        }
        n += ret;
    } while (n < sizeof(msg));

    *pfd = qemu_chr_fe_get_msgfd(s->server_chr);
    return msg;
}

static void ivshmem_recv_setup(IVShmemState *s, Error **errp)
{
    Error *err = NULL;
    int64_t msg;
    int fd;

    msg = ivshmem_recv_msg(s, &fd, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    if (msg != IVSHMEM_PROTOCOL_VERSION) {
        error_setg(errp, "server sent version %" PRId64 ", expecting %d",
                   msg, IVSHMEM_PROTOCOL_VERSION);
        return;
    }
    if (fd != -1) {
        error_setg(errp, "server sent invalid version message");
        return;
    }

    /*
     * ivshmem-server sends the remaining initial messages in a fixed
     * order, but the device has always accepted them in any order.
     * Stay as compatible as practical, just in case people use
     * servers that behave differently.
     */

    /*
     * ivshmem_device_spec.txt has always required the ID message
     * right here, and ivshmem-server has always complied.  However,
     * older versions of the device accepted it out of order, but
     * broke when an interrupt setup message arrived before it.
     */
    msg = ivshmem_recv_msg(s, &fd, &err);
    if (err) {
        error_propagate(errp, err);
        return;
    }
    if (fd != -1 || msg < 0 || msg > IVSHMEM_MAX_PEERS) {
        error_setg(errp, "server sent invalid ID message");
        return;
    }
    s->vm_id = msg;

    /*
     * Receive more messages until we got shared memory.
     */
    do {
        msg = ivshmem_recv_msg(s, &fd, &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
        process_msg(s, msg, fd, &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }
    } while (msg != -1);

    /*
     * This function must either map the shared memory or fail.  The
     * loop above ensures that: it terminates normally only after it
     * successfully processed the server's shared memory message.
     * Assert that actually mapped the shared memory:
     */
    assert(s->ivshmem_bar2);
}

/* Select the MSI-X vectors used by device.
 * ivshmem maps events to vectors statically, so
 * we just enable all vectors on init and after reset. */
static void ivshmem_msix_vector_use(IVShmemState *s)
{
    PCIDevice *d = PCI_DEVICE(s);
    int i;

    for (i = 0; i < s->vectors; i++) {
        msix_vector_use(d, i);
    }
}

static void ivshmem_reset(DeviceState *d)
{
    IVShmemState *s = IVSHMEM(d);

    s->intrstatus = 0;
    s->intrmask = 0;
    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        ivshmem_msix_vector_use(s);
    }
}

static int ivshmem_setup_interrupts(IVShmemState *s)
{
    /* allocate QEMU callback data for receiving interrupts */
    s->msi_vectors = g_malloc0(s->vectors * sizeof(MSIVector));

    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        if (msix_init_exclusive_bar(PCI_DEVICE(s), s->vectors, 1)) {
            return -1;
        }

        IVSHMEM_DPRINTF("msix initialized (%d vectors)\n", s->vectors);
        ivshmem_msix_vector_use(s);
    }

    return 0;
}

static void ivshmem_enable_irqfd(IVShmemState *s)
{
    PCIDevice *pdev = PCI_DEVICE(s);
    int i;

    for (i = 0; i < s->peers[s->vm_id].nb_eventfds; i++) {
        Error *err = NULL;

        ivshmem_add_kvm_msi_virq(s, i, &err);
        if (err) {
            error_report_err(err);
            /* TODO do we need to handle the error? */
        }
    }

    if (msix_set_vector_notifiers(pdev,
                                  ivshmem_vector_unmask,
                                  ivshmem_vector_mask,
                                  ivshmem_vector_poll)) {
        error_report("ivshmem: msix_set_vector_notifiers failed");
    }
}

static void ivshmem_remove_kvm_msi_virq(IVShmemState *s, int vector)
{
    IVSHMEM_DPRINTF("ivshmem_remove_kvm_msi_virq vector:%d\n", vector);

    if (s->msi_vectors[vector].pdev == NULL) {
        return;
    }

    /* it was cleaned when masked in the frontend. */
    kvm_irqchip_release_virq(kvm_state, s->msi_vectors[vector].virq);

    s->msi_vectors[vector].pdev = NULL;
}

static void ivshmem_disable_irqfd(IVShmemState *s)
{
    PCIDevice *pdev = PCI_DEVICE(s);
    int i;

    for (i = 0; i < s->peers[s->vm_id].nb_eventfds; i++) {
        ivshmem_remove_kvm_msi_virq(s, i);
    }

    msix_unset_vector_notifiers(pdev);
}

static void ivshmem_write_config(PCIDevice *pdev, uint32_t address,
                                 uint32_t val, int len)
{
    IVShmemState *s = IVSHMEM(pdev);
    int is_enabled, was_enabled = msix_enabled(pdev);

    pci_default_write_config(pdev, address, val, len);
    is_enabled = msix_enabled(pdev);

    if (kvm_msi_via_irqfd_enabled()) {
        if (!was_enabled && is_enabled) {
            ivshmem_enable_irqfd(s);
        } else if (was_enabled && !is_enabled) {
            ivshmem_disable_irqfd(s);
        }
    }
}

static void desugar_shm(IVShmemState *s)
{
    Object *obj;
    char *path;

    obj = object_new("memory-backend-file");
    path = g_strdup_printf("/dev/shm/%s", s->shmobj);
    object_property_set_str(obj, path, "mem-path", &error_abort);
    g_free(path);
    object_property_set_int(obj, s->ivshmem_size, "size", &error_abort);
    object_property_set_bool(obj, true, "share", &error_abort);
    object_property_add_child(OBJECT(s), "internal-shm-backend", obj,
                              &error_abort);
    user_creatable_complete(obj, &error_abort);
    s->hostmem = MEMORY_BACKEND(obj);
}

static void pci_ivshmem_realize(PCIDevice *dev, Error **errp)
{
    IVShmemState *s = IVSHMEM(dev);
    Error *err = NULL;
    uint8_t *pci_conf;
    uint8_t attr = PCI_BASE_ADDRESS_SPACE_MEMORY |
        PCI_BASE_ADDRESS_MEM_PREFETCH;

    if (!!s->server_chr + !!s->shmobj + !!s->hostmem != 1) {
        error_setg(errp,
                   "You must specify either 'shm', 'chardev' or 'x-memdev'");
        return;
    }

    if (s->hostmem) {
        MemoryRegion *mr;

        if (s->sizearg) {
            g_warning("size argument ignored with hostmem");
        }

        mr = host_memory_backend_get_memory(s->hostmem, &error_abort);
        s->ivshmem_size = memory_region_size(mr);
    } else if (s->sizearg == NULL) {
        s->ivshmem_size = 4 << 20; /* 4 MB default */
    } else {
        char *end;
        int64_t size = qemu_strtosz(s->sizearg, &end);
        if (size < 0 || (size_t)size != size || *end != '\0'
            || !is_power_of_2(size)) {
            error_setg(errp, "Invalid size %s", s->sizearg);
            return;
        }
        s->ivshmem_size = size;
    }

    /* IRQFD requires MSI */
    if (ivshmem_has_feature(s, IVSHMEM_IOEVENTFD) &&
        !ivshmem_has_feature(s, IVSHMEM_MSI)) {
        error_setg(errp, "ioeventfd/irqfd requires MSI");
        return;
    }

    /* check that role is reasonable */
    if (s->role) {
        if (strncmp(s->role, "peer", 5) == 0) {
            s->master = ON_OFF_AUTO_OFF;
        } else if (strncmp(s->role, "master", 7) == 0) {
            s->master = ON_OFF_AUTO_ON;
        } else {
            error_setg(errp, "'role' must be 'peer' or 'master'");
            return;
        }
    } else {
        s->master = ON_OFF_AUTO_AUTO;
    }

    pci_conf = dev->config;
    pci_conf[PCI_COMMAND] = PCI_COMMAND_IO | PCI_COMMAND_MEMORY;

    /*
     * Note: we don't use INTx with IVSHMEM_MSI at all, so this is a
     * bald-faced lie then.  But it's a backwards compatible lie.
     */
    pci_config_set_interrupt_pin(pci_conf, 1);

    memory_region_init_io(&s->ivshmem_mmio, OBJECT(s), &ivshmem_mmio_ops, s,
                          "ivshmem-mmio", IVSHMEM_REG_BAR_SIZE);

    /* region for registers*/
    pci_register_bar(dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &s->ivshmem_mmio);

    if (s->ivshmem_64bit) {
        attr |= PCI_BASE_ADDRESS_MEM_TYPE_64;
    }

    if (s->shmobj) {
        desugar_shm(s);
    }

    if (s->hostmem != NULL) {
        IVSHMEM_DPRINTF("using hostmem\n");

        s->ivshmem_bar2 = host_memory_backend_get_memory(s->hostmem,
                                                         &error_abort);
    } else {
        IVSHMEM_DPRINTF("using shared memory server (socket = %s)\n",
                        s->server_chr->filename);

        /* we allocate enough space for 16 peers and grow as needed */
        resize_peers(s, 16);

        /*
         * Receive setup messages from server synchronously.
         * Older versions did it asynchronously, but that creates a
         * number of entertaining race conditions.
         */
        ivshmem_recv_setup(s, &err);
        if (err) {
            error_propagate(errp, err);
            return;
        }

        qemu_chr_add_handlers(s->server_chr, ivshmem_can_receive,
                              ivshmem_read, NULL, s);

        if (ivshmem_setup_interrupts(s) < 0) {
            error_setg(errp, "failed to initialize interrupts");
            return;
        }
    }

    vmstate_register_ram(s->ivshmem_bar2, DEVICE(s));
    pci_register_bar(PCI_DEVICE(s), 2, attr, s->ivshmem_bar2);

    if (s->master == ON_OFF_AUTO_AUTO) {
        s->master = s->vm_id == 0 ? ON_OFF_AUTO_ON : ON_OFF_AUTO_OFF;
    }

    if (!ivshmem_is_master(s)) {
        error_setg(&s->migration_blocker,
                   "Migration is disabled when using feature 'peer mode' in device 'ivshmem'");
        migrate_add_blocker(s->migration_blocker);
    }
}

static void pci_ivshmem_exit(PCIDevice *dev)
{
    IVShmemState *s = IVSHMEM(dev);
    int i;

    if (s->migration_blocker) {
        migrate_del_blocker(s->migration_blocker);
        error_free(s->migration_blocker);
    }

    if (memory_region_is_mapped(s->ivshmem_bar2)) {
        if (!s->hostmem) {
            void *addr = memory_region_get_ram_ptr(s->ivshmem_bar2);
            int fd;

            if (munmap(addr, s->ivshmem_size) == -1) {
                error_report("Failed to munmap shared memory %s",
                             strerror(errno));
            }

            fd = qemu_get_ram_fd(memory_region_get_ram_addr(s->ivshmem_bar2));
            close(fd);
        }

        vmstate_unregister_ram(s->ivshmem_bar2, DEVICE(dev));
    }

    if (s->peers) {
        for (i = 0; i < s->nb_peers; i++) {
            close_peer_eventfds(s, i);
        }
        g_free(s->peers);
    }

    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        msix_uninit_exclusive_bar(dev);
    }

    g_free(s->msi_vectors);
}

static bool test_msix(void *opaque, int version_id)
{
    IVShmemState *s = opaque;

    return ivshmem_has_feature(s, IVSHMEM_MSI);
}

static bool test_no_msix(void *opaque, int version_id)
{
    return !test_msix(opaque, version_id);
}

static int ivshmem_pre_load(void *opaque)
{
    IVShmemState *s = opaque;

    if (!ivshmem_is_master(s)) {
        error_report("'peer' devices are not migratable");
        return -EINVAL;
    }

    return 0;
}

static int ivshmem_post_load(void *opaque, int version_id)
{
    IVShmemState *s = opaque;

    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        ivshmem_msix_vector_use(s);
    }
    return 0;
}

static int ivshmem_load_old(QEMUFile *f, void *opaque, int version_id)
{
    IVShmemState *s = opaque;
    PCIDevice *pdev = PCI_DEVICE(s);
    int ret;

    IVSHMEM_DPRINTF("ivshmem_load_old\n");

    if (version_id != 0) {
        return -EINVAL;
    }

    ret = ivshmem_pre_load(s);
    if (ret) {
        return ret;
    }

    ret = pci_device_load(pdev, f);
    if (ret) {
        return ret;
    }

    if (ivshmem_has_feature(s, IVSHMEM_MSI)) {
        msix_load(pdev, f);
        ivshmem_msix_vector_use(s);
    } else {
        s->intrstatus = qemu_get_be32(f);
        s->intrmask = qemu_get_be32(f);
    }

    return 0;
}

static const VMStateDescription ivshmem_vmsd = {
    .name = "ivshmem",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = ivshmem_pre_load,
    .post_load = ivshmem_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, IVShmemState),

        VMSTATE_MSIX_TEST(parent_obj, IVShmemState, test_msix),
        VMSTATE_UINT32_TEST(intrstatus, IVShmemState, test_no_msix),
        VMSTATE_UINT32_TEST(intrmask, IVShmemState, test_no_msix),

        VMSTATE_END_OF_LIST()
    },
    .load_state_old = ivshmem_load_old,
    .minimum_version_id_old = 0
};

static Property ivshmem_properties[] = {
    DEFINE_PROP_CHR("chardev", IVShmemState, server_chr),
    DEFINE_PROP_STRING("size", IVShmemState, sizearg),
    DEFINE_PROP_UINT32("vectors", IVShmemState, vectors, 1),
    DEFINE_PROP_BIT("ioeventfd", IVShmemState, features, IVSHMEM_IOEVENTFD, false),
    DEFINE_PROP_BIT("msi", IVShmemState, features, IVSHMEM_MSI, true),
    DEFINE_PROP_STRING("shm", IVShmemState, shmobj),
    DEFINE_PROP_STRING("role", IVShmemState, role),
    DEFINE_PROP_UINT32("use64", IVShmemState, ivshmem_64bit, 1),
    DEFINE_PROP_END_OF_LIST(),
};

static void ivshmem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_ivshmem_realize;
    k->exit = pci_ivshmem_exit;
    k->config_write = ivshmem_write_config;
    k->vendor_id = PCI_VENDOR_ID_IVSHMEM;
    k->device_id = PCI_DEVICE_ID_IVSHMEM;
    k->class_id = PCI_CLASS_MEMORY_RAM;
    dc->reset = ivshmem_reset;
    dc->props = ivshmem_properties;
    dc->vmsd = &ivshmem_vmsd;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "Inter-VM shared memory";
}

static void ivshmem_check_memdev_is_busy(Object *obj, const char *name,
                                         Object *val, Error **errp)
{
    MemoryRegion *mr;

    mr = host_memory_backend_get_memory(MEMORY_BACKEND(val), &error_abort);
    if (memory_region_is_mapped(mr)) {
        char *path = object_get_canonical_path_component(val);
        error_setg(errp, "can't use already busy memdev: %s", path);
        g_free(path);
    } else {
        qdev_prop_allow_set_link_before_realize(obj, name, val, errp);
    }
}

static void ivshmem_init(Object *obj)
{
    IVShmemState *s = IVSHMEM(obj);

    object_property_add_link(obj, "x-memdev", TYPE_MEMORY_BACKEND,
                             (Object **)&s->hostmem,
                             ivshmem_check_memdev_is_busy,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE,
                             &error_abort);
}

static const TypeInfo ivshmem_info = {
    .name          = TYPE_IVSHMEM,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(IVShmemState),
    .instance_init = ivshmem_init,
    .class_init    = ivshmem_class_init,
};

static void ivshmem_register_types(void)
{
    type_register_static(&ivshmem_info);
}

type_init(ivshmem_register_types)
