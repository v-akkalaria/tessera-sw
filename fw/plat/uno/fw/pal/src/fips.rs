// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Measured firmware approval and legacy bulk-FP service state.

use tsra_fw_hsm_pal_traits::HsmResult;
use tsra_fw_uno_drivers_part_store::HsmPartId;
use tsra_fw_uno_drivers_part_store::NUM_PARTITIONS;
use tsra_fw_uno_drivers_part_store::PartStore;
use tsra_fw_uno_reg_soc::hsm_dtcm;
use tsra_fw_uno_reg_soc::io_gsram;

use crate::UnoHsmPal;

impl UnoHsmPal {
    pub(crate) fn init_fips_approval(&self) -> HsmResult<()> {
        // SAFETY: SP publishes the last byte of this boot block before CP1 starts.
        let approved = unsafe {
            ((io_gsram::IO_GSRAM_BASE
                + io_gsram::POR_MEASUREMENTS_OFFSET
                + io_gsram::POR_MEASUREMENTS_SIZE
                - 1) as *const u8)
                .read_volatile()
                == 1
        };
        for index in 0..NUM_PARTITIONS {
            let pid = HsmPartId::from(index as u8);
            self.set_firmware_fips_approved(pid, approved);
            self.sync_fp_fips_approval(pid)?;
        }
        Ok(())
    }

    pub(crate) fn firmware_fips_approved(&self, pid: HsmPartId) -> bool {
        // SAFETY: pid is validated by the partition-store caller; this fixed
        // DTCM byte is CP1-owned and read by Admin through its global alias.
        unsafe {
            ((hsm_dtcm::HSM_DTCM_BASE + hsm_dtcm::FIPS_APPROVED_OFFSET + u32::from(u8::from(pid)))
                as *const u8)
                .read_volatile()
                == 1
        }
    }

    fn set_firmware_fips_approved(&self, pid: HsmPartId, approved: bool) {
        // SAFETY: this is the CP1-owned per-function firmware-status byte.
        unsafe {
            ((hsm_dtcm::HSM_DTCM_BASE + hsm_dtcm::FIPS_APPROVED_OFFSET + u32::from(u8::from(pid)))
                as *mut u8)
                .write_volatile(u8::from(approved));
        }
        cortex_m::asm::dmb();
    }

    pub(crate) fn sync_fp_fips_approval(&self, pid: HsmPartId) -> HsmResult<()> {
        let approved =
            self.firmware_fips_approved(pid) && PartStore::partition(pid)?.fips_status() == 1;
        self.set_fp_fips_approved(pid, approved);
        Ok(())
    }

    pub(crate) fn set_fp_fips_approved(&self, pid: HsmPartId, approved: bool) {
        #[cfg(feature = "bulk_crypto")]
        {
            // Legacy FP2's shared 65-byte service-indicator array. It is not
            // part of the Rust PQC mailbox layout.
            const FP_FIPS_APPROVED_BASE: usize = 0xA342_1C60;
            cortex_m::asm::dmb();
            // SAFETY: validated function index into the legacy FP2 shared ABI.
            unsafe {
                ((FP_FIPS_APPROVED_BASE + usize::from(u8::from(pid))) as *mut u8)
                    .write_volatile(u8::from(approved));
            }
            cortex_m::asm::dsb();
        }
        #[cfg(not(feature = "bulk_crypto"))]
        let _ = (pid, approved);
    }

    #[cfg(feature = "fips_validation_hooks")]
    pub(crate) fn toggle_firmware_fips_approval(&self, pid: HsmPartId) -> HsmResult<()> {
        PartStore::partition(pid)?;
        self.set_firmware_fips_approved(pid, !self.firmware_fips_approved(pid));
        self.sync_fp_fips_approval(pid)
    }
}
