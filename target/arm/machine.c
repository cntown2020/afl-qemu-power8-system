#include "qemu/osdep.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/boards.h"
#include "qemu/error-report.h"
#include "sysemu/kvm.h"
#include "kvm_arm.h"
#include "internals.h"
#include "migration/cpu.h"

static bool vfp_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_VFP);
}

static int get_fpscr(QEMUFile *f, void *opaque, size_t size,
                     VMStateField *field)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val = qemu_get_be32(f);

    vfp_set_fpscr(env, val);
    return 0;
}

static int put_fpscr(QEMUFile *f, void *opaque, size_t size,
                     VMStateField *field, QJSON *vmdesc)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    qemu_put_be32(f, vfp_get_fpscr(env));
    return 0;
}

static const VMStateInfo vmstate_fpscr = {
    .name = "fpscr",
    .get = get_fpscr,
    .put = put_fpscr,
};

static const VMStateDescription vmstate_vfp = {
    .name = "cpu/vfp",
    .version_id = 3,
    .minimum_version_id = 3,
    .needed = vfp_needed,
    .fields = (VMStateField[]) {
        VMSTATE_FLOAT64_ARRAY(env.vfp.regs, ARMCPU, 64),
        /* The xregs array is a little awkward because element 1 (FPSCR)
         * requires a specific accessor, so we have to split it up in
         * the vmstate:
         */
        VMSTATE_UINT32(env.vfp.xregs[0], ARMCPU),
        VMSTATE_UINT32_SUB_ARRAY(env.vfp.xregs, ARMCPU, 2, 14),
        {
            .name = "fpscr",
            .version_id = 0,
            .size = sizeof(uint32_t),
            .info = &vmstate_fpscr,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_END_OF_LIST()
    }
};

static bool iwmmxt_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_IWMMXT);
}

static const VMStateDescription vmstate_iwmmxt = {
    .name = "cpu/iwmmxt",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = iwmmxt_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT64_ARRAY(env.iwmmxt.regs, ARMCPU, 16),
        VMSTATE_UINT32_ARRAY(env.iwmmxt.cregs, ARMCPU, 16),
        VMSTATE_END_OF_LIST()
    }
};

static bool m_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_M);
}

static const VMStateDescription vmstate_m_faultmask_primask = {
    .name = "cpu/m/faultmask-primask",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.faultmask[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.primask[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_m = {
    .name = "cpu/m",
    .version_id = 4,
    .minimum_version_id = 4,
    .needed = m_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.vecbase[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.basepri[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.control[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.v7m.ccr, ARMCPU),
        VMSTATE_UINT32(env.v7m.cfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.hfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.dfsr, ARMCPU),
        VMSTATE_UINT32(env.v7m.mmfar, ARMCPU),
        VMSTATE_UINT32(env.v7m.bfar, ARMCPU),
        VMSTATE_UINT32(env.v7m.mpu_ctrl, ARMCPU),
        VMSTATE_INT32(env.v7m.exception, ARMCPU),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_m_faultmask_primask,
        NULL
    }
};

static bool thumb2ee_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_THUMB2EE);
}

static const VMStateDescription vmstate_thumb2ee = {
    .name = "cpu/thumb2ee",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = thumb2ee_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.teecr, ARMCPU),
        VMSTATE_UINT32(env.teehbr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav7_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_PMSA) &&
           arm_feature(env, ARM_FEATURE_V7) &&
           !arm_feature(env, ARM_FEATURE_V8);
}

static bool pmsav7_rgnr_vmstate_validate(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;

    return cpu->env.pmsav7.rnr < cpu->pmsav7_dregion;
}

static const VMStateDescription vmstate_pmsav7 = {
    .name = "cpu/pmsav7",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav7_needed,
    .fields = (VMStateField[]) {
        VMSTATE_VARRAY_UINT32(env.pmsav7.drbar, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav7.drsr, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav7.dracr, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VALIDATE("rgnr is valid", pmsav7_rgnr_vmstate_validate),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav7_rnr_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    /* For R profile cores pmsav7.rnr is migrated via the cpreg
     * "RGNR" definition in helper.h. For M profile we have to
     * migrate it separately.
     */
    return arm_feature(env, ARM_FEATURE_M);
}

static const VMStateDescription vmstate_pmsav7_rnr = {
    .name = "cpu/pmsav7-rnr",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav7_rnr_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.pmsav7.rnr, ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool pmsav8_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V8);
}

static const VMStateDescription vmstate_pmsav8 = {
    .name = "cpu/pmsav8",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = pmsav8_needed,
    .fields = (VMStateField[]) {
        VMSTATE_VARRAY_UINT32(env.pmsav8.rbar, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_VARRAY_UINT32(env.pmsav8.rlar, ARMCPU, pmsav7_dregion, 0,
                              vmstate_info_uint32, uint32_t),
        VMSTATE_UINT32(env.pmsav8.mair0[M_REG_NS], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair1[M_REG_NS], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static bool m_security_needed(void *opaque)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;

    return arm_feature(env, ARM_FEATURE_M_SECURITY);
}

static const VMStateDescription vmstate_m_security = {
    .name = "cpu/m-security",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = m_security_needed,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32(env.v7m.secure, ARMCPU),
        VMSTATE_UINT32(env.v7m.basepri[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.primask[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.faultmask[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.control[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.v7m.vecbase[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair0[M_REG_S], ARMCPU),
        VMSTATE_UINT32(env.pmsav8.mair1[M_REG_S], ARMCPU),
        VMSTATE_END_OF_LIST()
    }
};

static int get_cpsr(QEMUFile *f, void *opaque, size_t size,
                    VMStateField *field)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val = qemu_get_be32(f);

    if (arm_feature(env, ARM_FEATURE_M)) {
        if (val & XPSR_EXCP) {
            /* This is a CPSR format value from an older QEMU. (We can tell
             * because values transferred in XPSR format always have zero
             * for the EXCP field, and CPSR format will always have bit 4
             * set in CPSR_M.) Rearrange it into XPSR format. The significant
             * differences are that the T bit is not in the same place, the
             * primask/faultmask info may be in the CPSR I and F bits, and
             * we do not want the mode bits.
             * We know that this cleanup happened before v8M, so there
             * is no complication with banked primask/faultmask.
             */
            uint32_t newval = val;

            assert(!arm_feature(env, ARM_FEATURE_M_SECURITY));

            newval &= (CPSR_NZCV | CPSR_Q | CPSR_IT | CPSR_GE);
            if (val & CPSR_T) {
                newval |= XPSR_T;
            }
            /* If the I or F bits are set then this is a migration from
             * an old QEMU which still stored the M profile FAULTMASK
             * and PRIMASK in env->daif. For a new QEMU, the data is
             * transferred using the vmstate_m_faultmask_primask subsection.
             */
            if (val & CPSR_F) {
                env->v7m.faultmask[M_REG_NS] = 1;
            }
            if (val & CPSR_I) {
                env->v7m.primask[M_REG_NS] = 1;
            }
            val = newval;
        }
        /* Ignore the low bits, they are handled by vmstate_m. */
        xpsr_write(env, val, ~XPSR_EXCP);
        return 0;
    }

    env->aarch64 = ((val & PSTATE_nRW) == 0);

    if (is_a64(env)) {
        pstate_write(env, val);
        return 0;
    }

    cpsr_write(env, val, 0xffffffff, CPSRWriteRaw);
    return 0;
}

static int put_cpsr(QEMUFile *f, void *opaque, size_t size,
                    VMStateField *field, QJSON *vmdesc)
{
    ARMCPU *cpu = opaque;
    CPUARMState *env = &cpu->env;
    uint32_t val;

    if (arm_feature(env, ARM_FEATURE_M)) {
        /* The low 9 bits are v7m.exception, which is handled by vmstate_m. */
        val = xpsr_read(env) & ~XPSR_EXCP;
    } else if (is_a64(env)) {
        val = pstate_read(env);
    } else {
        val = cpsr_read(env);
    }

    qemu_put_be32(f, val);
    return 0;
}

static const VMStateInfo vmstate_cpsr = {
    .name = "cpsr",
    .get = get_cpsr,
    .put = put_cpsr,
};

static int get_power(QEMUFile *f, void *opaque, size_t size,
                    VMStateField *field)
{
    ARMCPU *cpu = opaque;
    bool powered_off = qemu_get_byte(f);
    cpu->power_state = powered_off ? PSCI_OFF : PSCI_ON;
    return 0;
}

static int put_power(QEMUFile *f, void *opaque, size_t size,
                    VMStateField *field, QJSON *vmdesc)
{
    ARMCPU *cpu = opaque;

    /* Migration should never happen while we transition power states */

    if (cpu->power_state == PSCI_ON ||
        cpu->power_state == PSCI_OFF) {
        bool powered_off = (cpu->power_state == PSCI_OFF) ? true : false;
        qemu_put_byte(f, powered_off);
        return 0;
    } else {
        return 1;
    }
}

static const VMStateInfo vmstate_powered_off = {
    .name = "powered_off",
    .get = get_power,
    .put = put_power,
};

static void cpu_pre_save(void *opaque)
{
    ARMCPU *cpu = opaque;

    if (kvm_enabled()) {
        if (!write_kvmstate_to_list(cpu)) {
            /* This should never fail */
            abort();
        }
    } else {
        if (!write_cpustate_to_list(cpu)) {
            /* This should never fail. */
            abort();
        }
    }

    cpu->cpreg_vmstate_array_len = cpu->cpreg_array_len;
    memcpy(cpu->cpreg_vmstate_indexes, cpu->cpreg_indexes,
           cpu->cpreg_array_len * sizeof(uint64_t));
    memcpy(cpu->cpreg_vmstate_values, cpu->cpreg_values,
           cpu->cpreg_array_len * sizeof(uint64_t));
}

static int cpu_post_load(void *opaque, int version_id)
{
    ARMCPU *cpu = opaque;
    int i, v;

    /* Update the values list from the incoming migration data.
     * Anything in the incoming data which we don't know about is
     * a migration failure; anything we know about but the incoming
     * data doesn't specify retains its current (reset) value.
     * The indexes list remains untouched -- we only inspect the
     * incoming migration index list so we can match the values array
     * entries with the right slots in our own values array.
     */

    for (i = 0, v = 0; i < cpu->cpreg_array_len
             && v < cpu->cpreg_vmstate_array_len; i++) {
        if (cpu->cpreg_vmstate_indexes[v] > cpu->cpreg_indexes[i]) {
            /* register in our list but not incoming : skip it */
            continue;
        }
        if (cpu->cpreg_vmstate_indexes[v] < cpu->cpreg_indexes[i]) {
            /* register in their list but not ours: fail migration */
            return -1;
        }
        /* matching register, copy the value over */
        cpu->cpreg_values[i] = cpu->cpreg_vmstate_values[v];
        v++;
    }

    if (kvm_enabled()) {
        if (!write_list_to_kvmstate(cpu, KVM_PUT_FULL_STATE)) {
            return -1;
        }
        /* Note that it's OK for the TCG side not to know about
         * every register in the list; KVM is authoritative if
         * we're using it.
         */
        write_list_to_cpustate(cpu);
    } else {
        if (!write_list_to_cpustate(cpu)) {
            return -1;
        }
    }

    hw_breakpoint_update_all(cpu);
    hw_watchpoint_update_all(cpu);

    return 0;
}

const VMStateDescription vmstate_arm_cpu = {
    .name = "cpu",
    .version_id = 22,
    .minimum_version_id = 22,
    .pre_save = cpu_pre_save,
    .post_load = cpu_post_load,
    .fields = (VMStateField[]) {
        VMSTATE_UINT32_ARRAY(env.regs, ARMCPU, 16),
        VMSTATE_UINT64_ARRAY(env.xregs, ARMCPU, 32),
        VMSTATE_UINT64(env.pc, ARMCPU),
        {
            .name = "cpsr",
            .version_id = 0,
            .size = sizeof(uint32_t),
            .info = &vmstate_cpsr,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_UINT32(env.spsr, ARMCPU),
        VMSTATE_UINT64_ARRAY(env.banked_spsr, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.banked_r13, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.banked_r14, ARMCPU, 8),
        VMSTATE_UINT32_ARRAY(env.usr_regs, ARMCPU, 5),
        VMSTATE_UINT32_ARRAY(env.fiq_regs, ARMCPU, 5),
        VMSTATE_UINT64_ARRAY(env.elr_el, ARMCPU, 4),
        VMSTATE_UINT64_ARRAY(env.sp_el, ARMCPU, 4),
        /* The length-check must come before the arrays to avoid
         * incoming data possibly overflowing the array.
         */
        VMSTATE_INT32_POSITIVE_LE(cpreg_vmstate_array_len, ARMCPU),
        VMSTATE_VARRAY_INT32(cpreg_vmstate_indexes, ARMCPU,
                             cpreg_vmstate_array_len,
                             0, vmstate_info_uint64, uint64_t),
        VMSTATE_VARRAY_INT32(cpreg_vmstate_values, ARMCPU,
                             cpreg_vmstate_array_len,
                             0, vmstate_info_uint64, uint64_t),
        VMSTATE_UINT64(env.exclusive_addr, ARMCPU),
        VMSTATE_UINT64(env.exclusive_val, ARMCPU),
        VMSTATE_UINT64(env.exclusive_high, ARMCPU),
        VMSTATE_UINT64(env.features, ARMCPU),
        VMSTATE_UINT32(env.exception.syndrome, ARMCPU),
        VMSTATE_UINT32(env.exception.fsr, ARMCPU),
        VMSTATE_UINT64(env.exception.vaddress, ARMCPU),
        VMSTATE_TIMER_PTR(gt_timer[GTIMER_PHYS], ARMCPU),
        VMSTATE_TIMER_PTR(gt_timer[GTIMER_VIRT], ARMCPU),
        {
            .name = "power_state",
            .version_id = 0,
            .size = sizeof(bool),
            .info = &vmstate_powered_off,
            .flags = VMS_SINGLE,
            .offset = 0,
        },
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription*[]) {
        &vmstate_vfp,
        &vmstate_iwmmxt,
        &vmstate_m,
        &vmstate_thumb2ee,
        /* pmsav7_rnr must come before pmsav7 so that we have the
         * region number before we test it in the VMSTATE_VALIDATE
         * in vmstate_pmsav7.
         */
        &vmstate_pmsav7_rnr,
        &vmstate_pmsav7,
        &vmstate_pmsav8,
        &vmstate_m_security,
        NULL
    }
};
