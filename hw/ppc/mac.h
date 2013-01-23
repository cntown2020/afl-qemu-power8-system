/*
 * QEMU PowerMac emulation shared definitions and prototypes
 *
 * Copyright (c) 2004-2007 Fabrice Bellard
 * Copyright (c) 2007 Jocelyn Mayer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#if !defined(__PPC_MAC_H__)
#define __PPC_MAC_H__

#include "exec/memory.h"

/* SMP is not enabled, for now */
#define MAX_CPUS 1

#define BIOS_SIZE     (1024 * 1024)
#define BIOS_FILENAME "ppc_rom.bin"
#define NVRAM_SIZE        0x2000
#define PROM_FILENAME    "openbios-ppc"
#define PROM_ADDR         0xfff00000

#define KERNEL_LOAD_ADDR 0x01000000
#define KERNEL_GAP       0x00100000

#define ESCC_CLOCK 3686400

/* Cuda */
void cuda_init (MemoryRegion **cuda_mem, qemu_irq irq);

/* MacIO */
#define TYPE_OLDWORLD_MACIO "macio-oldworld"
#define TYPE_NEWWORLD_MACIO "macio-newworld"
void macio_init(PCIDevice *dev,
                MemoryRegion *pic_mem, MemoryRegion *dbdma_mem,
                MemoryRegion *cuda_mem, void *nvram,
                int nb_ide, MemoryRegion **ide_mem, MemoryRegion *escc_mem);

/* Heathrow PIC */
qemu_irq *heathrow_pic_init(MemoryRegion **pmem,
                            int nb_cpus, qemu_irq **irqs);

/* Grackle PCI */
#define TYPE_GRACKLE_PCI_HOST_BRIDGE "grackle-pcihost"
PCIBus *pci_grackle_init(uint32_t base, qemu_irq *pic,
                         MemoryRegion *address_space_mem,
                         MemoryRegion *address_space_io);

/* UniNorth PCI */
PCIBus *pci_pmac_init(qemu_irq *pic,
                      MemoryRegion *address_space_mem,
                      MemoryRegion *address_space_io);
PCIBus *pci_pmac_u3_init(qemu_irq *pic,
                         MemoryRegion *address_space_mem,
                         MemoryRegion *address_space_io);

/* Mac NVRAM */
typedef struct MacIONVRAMState MacIONVRAMState;

MacIONVRAMState *macio_nvram_init (hwaddr size,
                                   unsigned int it_shift);
void macio_nvram_setup_bar(MacIONVRAMState *s, MemoryRegion *bar,
                           hwaddr mem_base);
void pmac_format_nvram_partition (MacIONVRAMState *nvr, int len);
uint8_t macio_nvram_read(MacIONVRAMState *s, uint32_t addr);
void macio_nvram_write(MacIONVRAMState *s, uint32_t addr, uint8_t val);
#endif /* !defined(__PPC_MAC_H__) */
