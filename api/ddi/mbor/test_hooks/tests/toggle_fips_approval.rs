// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MBOR approval validation on a dedicated Uno EVB with FIPS hooks.

#[allow(clippy::unwrap_used)]
mod common;

use common::*;
use test_with_tracing::test;
use tsra_ddi::Ddi;
use tsra_ddi::DdiError;
use tsra_ddi::DdiTransport;
use tsra_ddi_mbor_test_hooks::helper_test_action_cmd;
use tsra_ddi_mbor_test_hooks::TestActionRequest;
use tsra_ddi_mbor_test_hooks::DDI_OP_TEST_ACTION;
use tsra_ddi_mbor_types::DdiApiRev;
use tsra_ddi_mbor_types::DdiDeviceKind;
use tsra_ddi_mbor_types::DdiStatus;

type TestDev = <DdiTest as Ddi>::Dev;
const REV: Option<DdiApiRev> = Some(DdiApiRev { major: 1, minor: 0 });

#[derive(Debug, PartialEq, Eq)]
struct Indicators {
    mode: bool,
    discovery: bool,
    service: bool,
}

impl Indicators {
    fn read(dev: &TestDev) -> Result<Self, DdiError> {
        let info = helper_get_device_info(dev, None, REV)?;
        let service = helper_get_session_encryption_key(dev, None, REV)?;
        Ok(Self {
            mode: info.data.fips_approved,
            discovery: info.hdr.fips_approved,
            service: service.hdr.fips_approved,
        })
    }

    fn expected(approved: bool) -> Self {
        Self {
            mode: approved,
            discovery: true,
            service: approved,
        }
    }
}

#[test]
#[ignore = "requires one disposable physical Uno EVB with fips_validation_hooks"]
fn test_toggle_fips_approved_state() {
    assert!(
        std::env::var_os("TSRA_USE_TPM").is_none(),
        "requires mock sealing"
    );
    let _lock = HardwareTestLock::acquire();
    let ddi = DdiTest::default();
    assert_eq!(ddi.transport(), Some(DdiTransport::Ioctl));
    let devices = ddi.dev_info_list();
    assert_eq!(
        devices.len(),
        1,
        "expose only the dedicated EVB test device"
    );
    let path = &devices[0].path;
    let mut dev = ddi.open_dev(path).expect("open dedicated EVB device");
    let info = helper_get_device_info(&dev, None, REV).expect("read initial device info");
    assert_eq!(info.data.kind, DdiDeviceKind::Physical);

    let initial_approved = info.data.fips_approved;
    let fresh = if initial_approved {
        false
    } else {
        match helper_get_sealed_bk3(&dev) {
            Ok(_) => false,
            Err(DdiError::DdiStatus(DdiStatus::Bk3NotSecurelyProvisioned)) => true,
            Err(DdiError::DdiStatus(
                status @ (DdiStatus::SealedBk3NotPresent | DdiStatus::UnsupportedCmd),
            )) => {
                println!("Skipping approval validation: GetSealedBk3 returned {status:?}");
                return;
            }
            Err(err) => panic!("unexpected GetSealedBk3 error: {err:?}"),
        }
    };

    // Reset test credentials without replacing an existing sealed BK3.
    common_cleanup(&mut dev, &ddi, path, None);
    let expected_approved = if fresh {
        let firmware_approved = provision_mock_secure_bk3(&dev);
        let info = helper_get_device_info(&dev, None, REV).expect("read mode after SecureInitBk3");
        assert_eq!(info.data.fips_approved, firmware_approved);
        println!("SecureInitBk3: effective approval = {firmware_approved}");
        firmware_approved
    } else {
        // The shared session fixture falls back to legacy InitBk3 if nothing
        // is sealed. Do not let a reset turn this branch into legacy setup.
        helper_get_sealed_bk3(&dev).expect("existing sealed BK3 must survive credential reset");
        initial_approved
    };

    let observer = ddi
        .open_dev(path)
        .expect("open observer on the same partition");
    let session_id = establish_test_session(&dev, &ddi, path);
    let baseline = Indicators::read(&observer).expect("read baseline indicators");
    assert_eq!(baseline, Indicators::expected(expected_approved));
    println!("baseline: {baseline:?}");

    if !fresh || !expected_approved {
        let toggled = helper_test_action_cmd(
            &mut dev,
            session_id,
            TestActionRequest::ToggleFipsApprovedState,
        )
        .expect("ToggleFipsApprovedState (requires fips_validation_hooks)");
        // Restore the firmware state even if the intermediate read failed.
        let during = Indicators::read(&observer);
        let restored = helper_test_action_cmd(
            &mut dev,
            session_id,
            TestActionRequest::ToggleFipsApprovedState,
        )
        .expect("restore firmware approval");
        let after = Indicators::read(&observer).expect("read restored indicators");

        for reply in [toggled, restored] {
            assert_eq!(reply.hdr.op, DDI_OP_TEST_ACTION);
            assert_eq!(reply.hdr.sess_id, Some(session_id));
            assert_eq!(reply.hdr.status, DdiStatus::Success);
            assert!(!reply.hdr.fips_approved);
            assert!(reply.data.result.is_none());
        }
        let during = during.expect("read indicators after toggle");
        println!("toggled: {during:?}\nrestored: {after:?}");
        assert_eq!(
            during,
            Indicators::expected(!expected_approved),
            "sealed BK3 must have been provisioned via SecureInitBk3, not legacy InitBk3"
        );
        assert_eq!(after, baseline);
    }

    helper_close_session(&dev, Some(session_id), REV).expect("close test session");
}
