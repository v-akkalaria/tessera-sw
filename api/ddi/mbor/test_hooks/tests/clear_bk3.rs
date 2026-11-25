// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ClearBk3 validation against a physical device with fips_validation_hooks.
//!
//! Run after secure BK3 provisioning/sealing on a dedicated test device.
//! ClearBk3 zeroizes BK_BOOT, sealed BK3 and the derived session key, and
//! resets provisioning. The next init regenerates BK_BOOT without reallocating.
//! Firmware without the FIPS-validation action returns UnsupportedCmd.

#![allow(clippy::unwrap_used)]

mod common;

use common::common_cleanup;
use common::common_setup;
use common::ddi_dev_test;
use common::helper_common_establish_credential_no_unwrap;
use common::helper_get_sealed_bk3;
use common::provision_mock_secure_bk3;
use common::TEST_CRED_ID;
use common::TEST_CRED_PIN;
use test_with_tracing::test;
use tsra_ddi::DdiError;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_test_hooks::DDI_OP_TEST_ACTION;
use tsra_ddi_mbor_types::DdiStatus;

/// Requires mock sealing; TPM-backed provisioning is not supported.
#[test]
fn test_clear_bk3() {
    if std::env::var_os("TSRA_USE_TPM").is_some() {
        eprintln!("Skipping ClearBk3: this test requires mock sealing");
        return;
    }
    ddi_dev_test(
        common_setup,
        common_cleanup,
        |dev, ddi, path, session_id| {
            let before = helper_get_sealed_bk3(dev).expect("BK3 must be provisioned and sealed");
            assert!(!before.data.sealed_bk3.is_empty());

            let resp = helper_test_action_cmd(dev, session_id, TestActionRequest::ClearBk3);
            if matches!(&resp, Err(DdiError::DdiStatus(DdiStatus::UnsupportedCmd))) {
                println!("Firmware is not built with fips_validation_hooks.");
                return;
            }
            let resp = resp.expect("ClearBk3");
            assert_eq!(resp.hdr.op, DDI_OP_TEST_ACTION);
            assert_eq!(resp.hdr.sess_id, Some(session_id));
            assert_eq!(resp.hdr.status, DdiStatus::Success);
            assert!(resp.data.result.is_none());

            assert!(matches!(
                helper_get_sealed_bk3(dev),
                Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned))
            ));
            // Clear retains the active credential; NSSR removes it while
            // preserving the allocation and cleared state until the next init.
            common_cleanup(dev, ddi, path, Some(session_id));
            provision_mock_secure_bk3(dev);
            helper_common_establish_credential_no_unwrap(dev, TEST_CRED_ID, TEST_CRED_PIN)
                .expect("establish with reprovisioned BK3");
        },
    );
}
