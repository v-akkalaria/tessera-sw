// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Std Uno PAL — host-native Uno HSM platform abstraction layer.
//!
//! Implements the HSM PAL traits ([`HsmPal`], [`HsmIoController`],
//! [`HsmGdmaController`]) for running HSM core logic natively on the
//! host without hardware or an emulator.
//!
//! # Architecture
//!
//! ```text
//! User (tokio)                    Embassy thread
//! ────────────                    ──────────────
//! HsmIoRequest ──► submit_rx ──► poll_io()
//!                                  alloc buffer slot
//!                                  wrap as StdHsmIo
//!                                  ▼
//!                                core recv_task / send_task
//!                                  ▼
//!                                complete_io()
//!                                  simulate delay (tokio worker)
//!                                  free buffer slot
//! HsmCqe      ◄─ reply_tx ◄── send response
//! ```
//!
//! ## Key components
//!
//! - [`StdHsmPal`] — implements PAL traits with channel-based IO
//!   transport and a tokio-backed worker pool for delay simulation.
//! - [`StdHsmIo`] — IO work item backed by a pool-allocated buffer
//!   slot. Implements [`HsmIo`] for the core's generic IO processing.
//! - [`BufferPool`](buf_pool::BufferPool) — pre-allocated 2KB + 8KB
//!   buffers with async bitmap allocation and waker-based backpressure.
//! - [`WorkerPool`](worker::WorkerPool) — dispatches delay tasks to
//!   tokio, wakes Embassy tasks on completion via cross-thread `Waker`.
//! - [`HsmIoRequest`] — request type for the submit channel.
//!
//! ## Thread model
//!
//! All PAL state (buffer pool, channels, wakers) lives on the Embassy
//! thread. The tokio runtime runs on separate threads and only
//! communicates via `Waker` (thread-safe). No mutexes are needed —
//! `Cell` and `RefCell` suffice for single-threaded Embassy access.
//!
//!
//! Everything except [`cmd`] (the IO wire format), `session` and the API
//! revision range is shared with the other std platform: the modules are
//! compiled from `fw/plat/std/common/pal_src` via `#[path]`, and the
//! drivers, buffer pool and worker pool come from `tsra_fw_hsm_std_common`.
//!
//! [`HsmPal`]: tsra_fw_hsm_pal_traits::HsmPal
//! [`HsmIoController`]: tsra_fw_hsm_pal_traits::HsmIoController
//! [`HsmGdmaController`]: tsra_fw_hsm_pal_traits::HsmGdmaController
//! [`HsmIo`]: tsra_fw_hsm_pal_traits::HsmIo

#[path = "../../../common/pal_src/aes.rs"]
mod aes;
#[path = "../../../common/pal_src/alloc.rs"]
mod alloc;
#[path = "../../../common/pal_src/bulk.rs"]
mod bulk;
#[path = "../../../common/pal_src/cert.rs"]
mod cert;
mod drivers;
#[path = "../../../common/pal_src/ecc.rs"]
mod ecc;
#[path = "../../../common/pal_src/gdma.rs"]
mod gdma;
#[path = "../../../common/pal_src/hash.rs"]
mod hash;
#[path = "../../../common/pal_src/hmac.rs"]
mod hmac;
#[path = "../../../common/pal_src/io.rs"]
mod io;
#[path = "../../../common/pal_src/kdf.rs"]
mod kdf;
#[path = "../../../common/pal_src/key_assurance.rs"]
mod key_assurance;
#[path = "../../../common/pal_src/key_masking.rs"]
mod key_masking;
#[path = "../../../common/pal_src/pal.rs"]
mod pal;
#[path = "../../../common/pal_src/part.rs"]
mod part;
#[path = "../../../common/pal_src/part_lock.rs"]
mod part_lock;
#[path = "../../../common/pal_src/pqc.rs"]
mod pqc;
#[path = "../../../common/pal_src/rng.rs"]
mod rng;
#[path = "../../../common/pal_src/rsa.rs"]
mod rsa;
#[path = "../../../common/pal_src/seed.rs"]
mod seed;
mod session;
mod transport;
#[path = "../../../common/pal_src/vault.rs"]
mod vault;

use tsra_fw_hsm_std_common::buf_pool;
use tsra_fw_hsm_std_common::worker;

/// Command-queue wire format of this platform: Uno's 16-dword SQE and
/// 4-dword CQE.
pub mod cmd {
    pub use tsra_fw_hsm_io::Cqe;
    pub use tsra_fw_hsm_io::CqeEntry;
    pub use tsra_fw_hsm_io::RawCqe;
    pub use tsra_fw_hsm_io::RawSqe;
    pub use tsra_fw_hsm_io::SqeEntry;
    pub use tsra_fw_hsm_io::CQE_DWORDS;
    pub use tsra_fw_hsm_io::SQE_DWORDS;
}

pub use alloc::StdScopedAlloc;

pub use io::HsmIoRequest;
pub use io::StdHsmIo;
pub use pal::StdHsmPal;
pub use part::HsmPartId;
pub use part::PartCommand;
pub use tsra_fw_hsm_bulk::RawBulkCqe;
pub use tsra_fw_hsm_bulk::RawBulkSqe;
use tsra_fw_hsm_pal_traits::*;

/// Uno emulation: API revision 1.x, Uno IO protocol.
impl HsmPalFeatures for StdHsmPal {
    type IoProtocol = UnoIo;
    const API_REV_MIN: HsmApiRevision = HsmApiRevision::new(1, 0);
    const API_REV_MAX: HsmApiRevision = HsmApiRevision::new(1, 1);
}

/// Crypto operands are little-endian (word-padded P-521 slots).
impl HsmCryptoOrder for StdHsmPal {
    const BYTE_ORDER: HsmByteOrder = HsmByteOrder::Le;
}

#[cfg(test)]
mod fips_tests {
    use tsra_ddi_mbor_codec::MborEncode;
    use tsra_ddi_mbor_types::*;
    use tsra_fw_hsm_core::Hsm;

    use super::*;

    #[repr(align(4096))]
    struct Page([u8; 4096]);

    async fn execute<D: MborEncode>(
        hsm: &Hsm<StdHsmPal>,
        submit: &async_channel::Sender<HsmIoRequest>,
        op: DdiOp,
        body: D,
        revision: Option<DdiApiRev>,
    ) -> Vec<u8> {
        let mut src = Page([0; 4096]);
        let mut dst = Page([0; 4096]);
        let hdr = DdiReqHdr {
            rev: revision,
            op,
            sess_id: None,
        };
        let len = DdiEncoder::encode_parts(hdr, body, &mut src.0, false).unwrap();
        let mut sqe = tsra_fw_hsm_io::SqeEntry::default();
        sqe.0[0] = 1 << 16;
        sqe.0[1] = len as u32;
        let source = src.0.as_ptr() as u64;
        sqe.0[2] = source as u32;
        sqe.0[3] = (source >> 32) as u32;
        sqe.0[6] = dst.0.len() as u32;
        let destination = dst.0.as_mut_ptr() as u64;
        sqe.0[7] = destination as u32;
        sqe.0[8] = (destination >> 32) as u32;
        let (tx, rx) = tokio::sync::oneshot::channel();
        submit
            .send(HsmIoRequest::cmd(HsmPartId::from(0u8), 0, 0, sqe.0, tx))
            .await
            .unwrap();
        let io = hsm.pal().poll_io().await.unwrap();
        hsm.handle_io(io).await;
        let cqe = rx.await.unwrap();
        assert_eq!(cqe[3] >> 17, 0, "transport failure");
        let len = (cqe[0] & 0xFFFF) as usize;
        dst.0[..len].to_vec()
    }

    async fn info(
        hsm: &Hsm<StdHsmPal>,
        submit: &async_channel::Sender<HsmIoRequest>,
    ) -> (bool, bool) {
        let bytes = execute(
            hsm,
            submit,
            DdiOp::GetDeviceInfo,
            DdiGetDeviceInfoReq {},
            Some(DdiApiRev { major: 1, minor: 1 }),
        )
        .await;
        let mut decoder = DdiDecoder::new(&bytes, false);
        let hdr: DdiRespHdr = decoder.decode_hdr().unwrap();
        let data: DdiGetDeviceInfoResp = decoder.decode_data().unwrap();
        assert_eq!(hdr.status, DdiStatus::Success);
        assert_eq!(data.tables, 1);
        (hdr.fips_approved, data.fips_approved)
    }

    #[tokio::test]
    async fn mbor_fips_mode_and_service_indicators() {
        let (submit, receive) = async_channel::bounded(1);
        let pal = StdHsmPal::new(receive, tokio::runtime::Handle::current());
        pal.part_alloc_internal(0, 1).await.unwrap();
        pal.part_enable_internal(0).await.unwrap();
        let hsm = Hsm::new(pal);
        let pid = HsmPartId::from(0u8);
        let rev = Some(DdiApiRev { major: 1, minor: 1 });

        assert_eq!(info(&hsm, &submit).await, (true, false));
        let bytes = execute(&hsm, &submit, DdiOp::GetApiRev, DdiGetApiRevReq {}, None).await;
        let hdr: DdiRespHdr = DdiDecoder::new(&bytes, false).decode_hdr().unwrap();
        assert!(hdr.fips_approved);

        hsm.pal().test_set_firmware_fips_approved(pid, true);
        assert_eq!(info(&hsm, &submit).await, (true, false));
        let bytes = execute(
            &hsm,
            &submit,
            DdiOp::GetEstablishCredEncryptionKey,
            DdiGetEstablishCredEncryptionKeyReq {},
            rev,
        )
        .await;
        let hdr: DdiRespHdr = DdiDecoder::new(&bytes, false).decode_hdr().unwrap();
        assert_eq!(hdr.status, DdiStatus::Success);
        assert!(hdr.fips_approved, "setup does not require BK3 yet");

        let (tx, _rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(pid, 0, tx);
        let credential = hsm.pal().dma_alloc(&io, 32).unwrap();
        credential.fill(0x71);
        hsm.pal()
            .part_prop_set_bytes(&io, HsmPartPropId::CREDENTIAL, credential)
            .unwrap();

        let bytes = execute(
            &hsm,
            &submit,
            DdiOp::GetSessionEncryptionKey,
            DdiGetSessionEncryptionKeyReq {},
            rev,
        )
        .await;
        let hdr: DdiRespHdr = DdiDecoder::new(&bytes, false).decode_hdr().unwrap();
        assert_eq!(hdr.status, DdiStatus::Success);
        assert!(!hdr.fips_approved, "ordinary services require secure BK3");

        let (tx, _rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(pid, 0, tx);
        hsm.pal().part_commit_bk3(&io, true, None).unwrap();
        assert_eq!(info(&hsm, &submit).await, (true, true));
        let bytes = execute(
            &hsm,
            &submit,
            DdiOp::GetSessionEncryptionKey,
            DdiGetSessionEncryptionKeyReq {},
            rev,
        )
        .await;
        let hdr: DdiRespHdr = DdiDecoder::new(&bytes, false).decode_hdr().unwrap();
        assert_eq!(hdr.status, DdiStatus::Success);
        assert!(hdr.fips_approved);

        hsm.pal().test_set_firmware_fips_approved(pid, false);
        assert_eq!(info(&hsm, &submit).await, (true, false));
        hsm.pal().test_set_firmware_fips_approved(pid, true);
        hsm.pal().part_disable_internal(0).unwrap();
        hsm.pal().part_enable_internal(0).await.unwrap();
        assert_eq!(info(&hsm, &submit).await, (true, true));

        let bytes = execute(
            &hsm,
            &submit,
            DdiOp::GetDeviceInfo,
            DdiGetDeviceInfoReq {},
            Some(DdiApiRev { major: 9, minor: 0 }),
        )
        .await;
        let hdr: DdiRespHdr = DdiDecoder::new(&bytes, false).decode_hdr().unwrap();
        assert_ne!(hdr.status, DdiStatus::Success);
        assert!(!hdr.fips_approved, "errors are never approved");

        hsm.pal().part_free_internal(0).unwrap();
        hsm.pal().part_alloc_internal(0, 1).await.unwrap();
        hsm.pal().part_enable_internal(0).await.unwrap();
        assert_eq!(info(&hsm, &submit).await, (true, false));
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let io = StdHsmIo::admin(pid, 0, tx);
        hsm.pal().part_commit_bk3(&io, false, None).unwrap();
        assert_eq!(
            info(&hsm, &submit).await,
            (true, false),
            "legacy stays unapproved"
        );
    }
}
