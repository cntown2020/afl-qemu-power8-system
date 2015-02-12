/*
 * bootloader support
 *
 * Copyright IBM, Corp. 2012
 *
 * Authors:
 *  Christian Borntraeger <borntraeger@de.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or (at your
 * option) any later version.  See the COPYING file in the top-level directory.
 *
 */

#include "sysemu/sysemu.h"
#include "cpu.h"
#include "elf.h"
#include "hw/loader.h"
#include "hw/sysbus.h"
#include "hw/s390x/virtio-ccw.h"
#include "hw/s390x/css.h"
#include "ipl.h"

#define KERN_IMAGE_START                0x010000UL
#define KERN_PARM_AREA                  0x010480UL
#define INITRD_START                    0x800000UL
#define INITRD_PARM_START               0x010408UL
#define INITRD_PARM_SIZE                0x010410UL
#define PARMFILE_START                  0x001000UL
#define ZIPL_IMAGE_START                0x009000UL
#define IPL_PSW_MASK                    (PSW_MASK_32 | PSW_MASK_64)

#define TYPE_S390_IPL "s390-ipl"
#define S390_IPL(obj) \
    OBJECT_CHECK(S390IPLState, (obj), TYPE_S390_IPL)
#if 0
#define S390_IPL_CLASS(klass) \
    OBJECT_CLASS_CHECK(S390IPLState, (klass), TYPE_S390_IPL)
#define S390_IPL_GET_CLASS(obj) \
    OBJECT_GET_CLASS(S390IPLState, (obj), TYPE_S390_IPL)
#endif

typedef struct S390IPLClass {
    /*< private >*/
    SysBusDeviceClass parent_class;
    /*< public >*/

    void (*parent_reset) (SysBusDevice *dev);
} S390IPLClass;

typedef struct S390IPLState {
    /*< private >*/
    SysBusDevice parent_obj;
    uint64_t start_addr;
    uint64_t bios_start_addr;
    bool enforce_bios;
    IplParameterBlock iplb;
    bool iplb_valid;

    /*< public >*/
    char *kernel;
    char *initrd;
    char *cmdline;
    char *firmware;
    uint8_t cssid;
    uint8_t ssid;
    uint16_t devno;
} S390IPLState;


static int s390_ipl_init(SysBusDevice *dev)
{
    S390IPLState *ipl = S390_IPL(dev);
    uint64_t pentry = KERN_IMAGE_START;
    int kernel_size;

    int bios_size;
    char *bios_filename;

    /*
     * Always load the bios if it was enforced,
     * even if an external kernel has been defined.
     */
    if (!ipl->kernel || ipl->enforce_bios) {
        if (bios_name == NULL) {
            bios_name = ipl->firmware;
        }

        bios_filename = qemu_find_file(QEMU_FILE_TYPE_BIOS, bios_name);
        if (bios_filename == NULL) {
            hw_error("could not find stage1 bootloader\n");
        }

        bios_size = load_elf(bios_filename, NULL, NULL, &ipl->bios_start_addr,
                             NULL, NULL, 1, ELF_MACHINE, 0);
        if (bios_size < 0) {
            bios_size = load_image_targphys(bios_filename, ZIPL_IMAGE_START,
                                            4096);
            ipl->bios_start_addr = ZIPL_IMAGE_START;
            if (bios_size > 4096) {
                hw_error("stage1 bootloader is > 4k\n");
            }
        }
        g_free(bios_filename);

        if (bios_size == -1) {
            hw_error("could not load bootloader '%s'\n", bios_name);
        }

        /* default boot target is the bios */
        ipl->start_addr = ipl->bios_start_addr;
    }

    if (ipl->kernel) {
        kernel_size = load_elf(ipl->kernel, NULL, NULL, &pentry, NULL,
                               NULL, 1, ELF_MACHINE, 0);
        if (kernel_size < 0) {
            kernel_size = load_image_targphys(ipl->kernel, 0, ram_size);
        }
        if (kernel_size < 0) {
            fprintf(stderr, "could not load kernel '%s'\n", ipl->kernel);
            return -1;
        }
        /*
         * Is it a Linux kernel (starting at 0x10000)? If yes, we fill in the
         * kernel parameters here as well. Note: For old kernels (up to 3.2)
         * we can not rely on the ELF entry point - it was 0x800 (the SALIPL
         * loader) and it won't work. For this case we force it to 0x10000, too.
         */
        if (pentry == KERN_IMAGE_START || pentry == 0x800) {
            ipl->start_addr = KERN_IMAGE_START;
            /* Overwrite parameters in the kernel image, which are "rom" */
            strcpy(rom_ptr(KERN_PARM_AREA), ipl->cmdline);
        } else {
            ipl->start_addr = pentry;
        }

        if (ipl->initrd) {
            ram_addr_t initrd_offset;
            int initrd_size;

            initrd_offset = INITRD_START;
            while (kernel_size + 0x100000 > initrd_offset) {
                initrd_offset += 0x100000;
            }
            initrd_size = load_image_targphys(ipl->initrd, initrd_offset,
                                              ram_size - initrd_offset);
            if (initrd_size == -1) {
                fprintf(stderr, "qemu: could not load initrd '%s'\n",
                        ipl->initrd);
                exit(1);
            }

            /*
             * we have to overwrite values in the kernel image,
             * which are "rom"
             */
            stq_p(rom_ptr(INITRD_PARM_START), initrd_offset);
            stq_p(rom_ptr(INITRD_PARM_SIZE), initrd_size);
        }
    }
    return 0;
}

static Property s390_ipl_properties[] = {
    DEFINE_PROP_STRING("kernel", S390IPLState, kernel),
    DEFINE_PROP_STRING("initrd", S390IPLState, initrd),
    DEFINE_PROP_STRING("cmdline", S390IPLState, cmdline),
    DEFINE_PROP_STRING("firmware", S390IPLState, firmware),
    DEFINE_PROP_BOOL("enforce_bios", S390IPLState, enforce_bios, false),
    DEFINE_PROP_END_OF_LIST(),
};

/*
 * In addition to updating the iplstate, this function returns:
 * - 0 if system was ipled with external kernel
 * - -1 if no valid boot device was found
 * - ccw id of the boot device otherwise
 */
static uint64_t s390_update_iplstate(CPUS390XState *env, S390IPLState *ipl)
{
    DeviceState *dev_st;

    if (ipl->iplb_valid) {
        ipl->cssid = 0;
        ipl->ssid = 0;
        ipl->devno = ipl->iplb.devno;
        goto out;
    }

    if (ipl->kernel) {
        return 0;
    }

    dev_st = get_boot_device(0);
    if (dev_st) {
        VirtioCcwDevice *ccw_dev = (VirtioCcwDevice *) object_dynamic_cast(
            OBJECT(qdev_get_parent_bus(dev_st)->parent),
                TYPE_VIRTIO_CCW_DEVICE);
        if (ccw_dev) {
            ipl->cssid = ccw_dev->sch->cssid;
            ipl->ssid = ccw_dev->sch->ssid;
            ipl->devno = ccw_dev->sch->devno;
            goto out;
        }
    }

    return -1;
out:
    return ipl->cssid << 24 | ipl->ssid << 16 | ipl->devno;
}

int s390_ipl_update_diag308(IplParameterBlock *iplb)
{
    S390IPLState *ipl;

    ipl = S390_IPL(object_resolve_path(TYPE_S390_IPL, NULL));
    if (ipl) {
        ipl->iplb = *iplb;
        ipl->iplb_valid = true;
        return 0;
    }
    return -1;
}

IplParameterBlock *s390_ipl_get_iplb(void)
{
    S390IPLState *ipl;

    ipl = S390_IPL(object_resolve_path(TYPE_S390_IPL, NULL));
    if (!ipl || !ipl->iplb_valid) {
        return NULL;
    }
    return &ipl->iplb;
}

static void s390_ipl_reset(DeviceState *dev)
{
    S390IPLState *ipl = S390_IPL(dev);
    S390CPU *cpu = S390_CPU(qemu_get_cpu(0));
    CPUS390XState *env = &cpu->env;

    env->psw.addr = ipl->start_addr;
    env->psw.mask = IPL_PSW_MASK;

    if (!ipl->kernel || ipl->iplb_valid) {
        env->psw.addr = ipl->bios_start_addr;
        env->regs[7] = s390_update_iplstate(env, ipl);
    }

    s390_cpu_set_state(CPU_STATE_OPERATING, cpu);
}

static void s390_ipl_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    SysBusDeviceClass *k = SYS_BUS_DEVICE_CLASS(klass);

    k->init = s390_ipl_init;
    dc->props = s390_ipl_properties;
    dc->reset = s390_ipl_reset;
}

static const TypeInfo s390_ipl_info = {
    .class_init = s390_ipl_class_init,
    .parent = TYPE_SYS_BUS_DEVICE,
    .name  = "s390-ipl",
    .instance_size  = sizeof(S390IPLState),
};

static void s390_ipl_register_types(void)
{
    type_register_static(&s390_ipl_info);
}

type_init(s390_ipl_register_types)
