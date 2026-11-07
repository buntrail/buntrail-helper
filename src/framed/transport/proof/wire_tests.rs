use super::*;
use std::sync::{Mutex, atomic::AtomicUsize};
struct Wire {
    socket: UnixStream,
    thread: Option<std::thread::JoinHandle<io::Result<()>>>,
    shared: Arc<Shared>,
    header: Header,
    original: GitMutationRequest,
    _dir: tempfile::TempDir,
}
impl Wire {
    fn new(negotiate: bool) -> Self {
        let (dir, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
        std::fs::create_dir(dir.path().join("uploads")).unwrap();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            runtime: uuid(dispatcher.terminal.runtime.supervisor_boot),
            binding: hex(&sha2::Sha256::digest(
                serde_json::to_vec(dispatcher.files.target()).unwrap(),
            )),
            dispatcher: Arc::new(dispatcher),
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        let (socket, server) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let state = shared.clone();
        let thread = std::thread::spawn(move || connection(server, &state, 1));
        let header = Header {
            major: 1,
            minor: 0,
            request_id: 1,
            context: None,
            operation_id: None,
            stream_id: None,
            sequence: None,
            message: Message::Hello {
                capabilities: buntrail_protocol::negotiation::CAPABILITIES
                    .iter()
                    .filter(|c| negotiate || **c != "git.worktree_proof")
                    .map(|c| c.to_string())
                    .collect(),
                max_header: 65536,
                max_payload: 1048576,
            },
        };
        let mut wire = Self {
            socket,
            thread: Some(thread),
            shared,
            header,
            original,
            _dir: dir,
        };
        wire.send(Vec::new());
        wire.receive().unwrap();
        wire.header.request_id = 2;
        wire.header.message = Message::Register {
            lease_id: uuid([1; 16]),
            client_id: uuid([2; 16]),
            workspace_id: uuid([3; 16]),
            target_binding: wire.shared.binding.clone(),
            runtime_generation: wire.shared.runtime.clone(),
        };
        wire.send(Vec::new());
        wire.receive().unwrap();
        wire.header.context = Some(Context {
            client_id: uuid([2; 16]),
            workspace_id: uuid([3; 16]),
            target_binding: wire.shared.binding.clone(),
            runtime_generation: wire.shared.runtime.clone(),
        });
        wire.header.request_id = 3;
        wire
    }
    fn send(&mut self, payload: Vec<u8>) {
        self.socket
            .write_all(
                &Frame {
                    header: self.header.clone(),
                    payload,
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
    }
    fn receive(&mut self) -> io::Result<Frame> {
        let mut prefix = [0; 8];
        self.socket.read_exact(&mut prefix)?;
        let size = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize
            + u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
        let mut bytes = vec![0; size];
        self.socket.read_exact(&mut bytes)?;
        let mut encoded = prefix.to_vec();
        encoded.extend(bytes);
        Ok(Decoder::default()
            .push_authorized(&encoded, |_| true)
            .map_err(error)?
            .remove(0))
    }
    fn body(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        proof_codec::write_original(
            &mut bytes,
            &self.original,
            self.shared.dispatcher.files.target(),
        )
        .unwrap();
        bytes
    }
    fn begin(&mut self, length: u64) -> Frame {
        self.begin_action(length, ProofAction::Prepare)
    }
    fn begin_action(&mut self, length: u64, action: ProofAction) -> Frame {
        self.header.operation_id = Some(uuid(self.original.operation.0));
        self.header.stream_id = Some(uuid([9; 16]));
        self.header.sequence = None;
        self.header.message = Message::ProofLookupBegin {
            transfer_id: uuid([9; 16]),
            total_length: length,
            action,
            lease_id: uuid([1; 16]),
        };
        self.send(Vec::new());
        self.receive().unwrap()
    }
    fn original_chunks(&mut self, body: &[u8]) {
        for (i, chunk) in body.chunks(65536).enumerate() {
            self.header.sequence = Some(i as u64);
            self.header.message = Message::ProofLookupChunk {
                transfer_id: uuid([9; 16]),
                offset: (i * 65536) as u64,
            };
            self.send(chunk.to_vec());
            assert!(matches!(
                self.receive().unwrap().header.message,
                Message::Credit { .. }
            ));
        }
    }
    fn end(&mut self, body: &[u8]) {
        self.header.sequence = Some(body.len().div_ceil(65536) as u64);
        self.header.message = Message::ProofLookupEnd {
            transfer_id: uuid([9; 16]),
            sha256: hex(&sha2::Sha256::digest(body)),
        };
        self.send(Vec::new());
    }
    fn idle_counts(&self) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.shared.controls.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(self.shared.controls.load(Ordering::SeqCst), 0);
    }
}
impl Drop for Wire {
    fn drop(&mut self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join().unwrap();
        }
        self.idle_counts();
    }
}
#[test]
fn unnegotiated_proof_is_refused_without_losing_registered_connection() {
    let mut wire = Wire::new(false);
    let body = wire.body();
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::Error { .. }
    ));
    wire.header.operation_id = None;
    wire.header.stream_id = None;
    wire.header.request_id += 1;
    wire.header.message = Message::Authentication {
        ssh_auth_sock: None,
    };
    wire.send(Vec::new());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::Ack {}
    ));
}
#[test]
fn malformed_original_frames_never_establish_a_new_no_effect_receipt() {
    for case in [
        "sequence",
        "offset",
        "length",
        "hash",
        "operation",
        "type",
        "partial-cancel",
        "repeated-end",
    ] {
        let mut wire = Wire::new(true);
        let body = wire.body();
        let length = body.len() as u64 + u64::from(case == "length");
        assert!(matches!(
            wire.begin(length).header.message,
            Message::ProofLookupReady { .. }
        ));
        wire.header.sequence = Some(if case == "sequence" { 1 } else { 0 });
        wire.header.message = Message::ProofLookupChunk {
            transfer_id: uuid([9; 16]),
            offset: if case == "offset" { 1 } else { 0 },
        };
        if case == "operation" {
            wire.header.operation_id = Some(uuid([255; 16]));
        }
        if case == "type" {
            wire.header.message = Message::ProofAliasesChunk {
                transfer_id: uuid([9; 16]),
                offset: 0,
            };
        }
        if case == "partial-cancel" {
            wire.send(body[..8].to_vec());
            wire.header.request_id = 4;
            wire.header.operation_id = None;
            wire.header.stream_id = None;
            wire.header.sequence = None;
            wire.header.message = Message::Cancel { request_id: 3 };
            wire.send(Vec::new());
            let reply = wire.receive().unwrap();
            assert!(!matches!(
                reply.header.message,
                Message::Receipt {
                    state: ReceiptState::Failed,
                    ..
                }
            ));
        } else {
            wire.send(body.clone());
            let response = wire.receive();
            if matches!(case, "sequence" | "offset" | "operation" | "type") {
                assert!(
                    response.is_err()
                        || matches!(
                            response.as_ref().map(|f| &f.header.message),
                            Ok(Message::Error { .. })
                        ),
                    "{case}: {response:?}"
                );
            } else {
                let response = response.unwrap();
                if case == "length" && matches!(response.header.message, Message::Error { .. }) {
                    assert!(
                        wire.shared
                            .dispatcher
                            .git
                            .existing_receipt_sync(&wire.original)
                            .unwrap()
                            .is_none()
                    );
                    continue;
                }
                assert!(
                    matches!(response.header.message, Message::Credit { .. }),
                    "{case}: {:?}",
                    response.header.message
                );
                wire.header.sequence = Some(1);
                wire.header.message = Message::ProofLookupEnd {
                    transfer_id: uuid([9; 16]),
                    sha256: if case == "hash" {
                        "00".repeat(32)
                    } else {
                        hex(&sha2::Sha256::digest(&body))
                    },
                };
                wire.send(Vec::new());
                if case == "repeated-end" {
                    wire.send(Vec::new());
                }
                let response = wire.receive();
                if case != "repeated-end" {
                    assert!(
                        response.is_err()
                            || matches!(
                                response.as_ref().map(|f| &f.header.message),
                                Ok(Message::Error { .. })
                            ),
                        "{case}: {response:?}"
                    );
                }
            }
        }
        assert!(
            wire.shared
                .dispatcher
                .git
                .existing_receipt_sync(&wire.original)
                .unwrap()
                .is_none(),
            "malformed {case} created a receipt"
        );
    }
}
#[test]
fn complete_original_receipt_wins_full_uploads_normal_work_and_maintenance() {
    let mut wire = Wire::new(true);
    let expected = wire
        .shared
        .dispatcher
        .git
        .mutate_sync(wire.original.clone(), &AtomicBool::new(false));
    assert!(matches!(expected.state, OperationState::Confirmed(_)));
    for n in 20..24 {
        wire.header.request_id = n;
        wire.header.operation_id = Some(uuid([n as u8; 16]));
        wire.header.stream_id = Some(uuid([n as u8; 16]));
        wire.header.message = Message::UploadBegin {
            transfer_id: uuid([n as u8; 16]),
            path_base64: STANDARD.encode(b"/unused"),
            total_length: 0,
        };
        wire.send(Vec::new());
        assert!(matches!(
            wire.receive().unwrap().header.message,
            Message::Ack {}
        ));
    }
    let mut owners = Vec::new();
    let mut inputs = Vec::new();
    for n in 0..256u16 {
        let mut identity = [0; 16];
        identity[..2].copy_from_slice(&n.to_be_bytes());
        let active = Arc::new(AtomicBool::new(true));
        let owner = ObservationOwner::authenticated(
            wire.shared.dispatcher.files.target().clone(),
            WorkspaceLease {
                client: ClientID([2; 16]),
                workspace: WorkspaceID(identity),
                lease: WorkspaceLeaseID(identity),
                runtime: wire.shared.dispatcher.terminal.runtime.clone(),
            },
            active.clone(),
        );
        inputs.push(
            wire.shared
                .dispatcher
                .git
                .observation_input(&owner)
                .unwrap(),
        );
        owners.push(active);
    }
    let scratch = [0u8; 65536];
    for _ in 0..8192 {
        inputs[0].append(&scratch).unwrap();
    }
    let stats = wire
        .shared
        .dispatcher
        .git
        .observation_storage_stats()
        .unwrap();
    assert_eq!(stats.bytes, 512 * 1024 * 1024);
    assert_eq!(stats.owners, 256);
    wire.shared.requests.store(8, Ordering::SeqCst);
    wire.shared
        .mutation_admission_closed
        .store(true, Ordering::SeqCst);
    wire.header.request_id = 30;
    let body = wire.body();
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    let Message::ProofExisting { receipt } = wire.receive().unwrap().header.message else {
        panic!("duplicate lookup lost reserved authority")
    };
    assert_eq!(
        receipt.core(wire.shared.dispatcher.files.target()).unwrap(),
        expected
    );
    wire.idle_counts();
    wire.header.request_id = 31;
    wire.original.operation = OperationID([201; 16]);
    wire.original.command = GitMutation::Checkout {
        reference: vec![b'x'; 65536],
    };
    let missing_body = wire.body();
    assert!(matches!(
        wire.begin_action(missing_body.len() as u64, ProofAction::Lookup)
            .header
            .message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&missing_body);
    wire.end(&missing_body);
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::ProofMissing {}
    ));
    let after = wire
        .shared
        .dispatcher
        .git
        .observation_storage_stats()
        .unwrap();
    assert_eq!(after.bytes, stats.bytes);
    assert_eq!(after.owners, stats.owners);
    assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 8);
    wire.idle_counts();
    drop(inputs);
    for owner in owners {
        owner.store(false, Ordering::SeqCst);
    }
    wire.shared.dispatcher.git.reap_observations();
    assert_eq!(
        wire.shared
            .dispatcher
            .git
            .observation_storage_stats()
            .unwrap()
            .bytes,
        0
    );
}
#[test]
fn receiving_original_capacity_and_partial_cancel_are_bounded() {
    let mut wire = Wire::new(true);
    let body = wire.body();
    for n in 30..34 {
        wire.header.request_id = n;
        assert!(matches!(
            wire.begin(body.len() as u64).header.message,
            Message::ProofLookupReady { .. }
        ));
    }
    assert_eq!(wire.shared.controls.load(Ordering::SeqCst), 4);
    wire.header.request_id = 34;
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::Error { .. }
    ));
    for n in 30..34 {
        wire.header.request_id = n + 10;
        wire.header.operation_id = None;
        wire.header.stream_id = None;
        wire.header.sequence = None;
        wire.header.message = Message::Cancel { request_id: n };
        wire.send(Vec::new());
    }
    wire.idle_counts();
    assert!(
        wire.shared
            .dispatcher
            .git
            .existing_receipt_sync(&wire.original)
            .unwrap()
            .is_none()
    );
}

#[test]
fn changed_replay_cancel_and_replaced_epoch_retire_both_input_parts() {
    for case in ["changed-replay", "cancel", "replacement"] {
        let mut wire = Wire::new(true);
        let body = wire.body();
        assert!(matches!(
            wire.begin(body.len() as u64).header.message,
            Message::ProofLookupReady { .. }
        ));
        wire.original_chunks(&body);
        wire.end(&body);
        let Message::ProofReady {
            original_transfer_id,
            ..
        } = wire.receive().unwrap().header.message
        else {
            panic!("normal replay ready missing")
        };
        wire.idle_counts();
        assert_eq!(
            wire.shared.requests.load(Ordering::SeqCst),
            1,
            "normal owner must hold the promoted guard"
        );
        wire.header.stream_id = Some(original_transfer_id.clone());
        wire.header.sequence = Some(0);
        wire.header.message = Message::ProofOriginalChunk {
            transfer_id: original_transfer_id.clone(),
            offset: 0,
        };
        let mut replay = body.clone();
        if case == "changed-replay" {
            *replay.last_mut().unwrap() ^= 1;
        }
        wire.send(replay.clone());
        assert!(matches!(
            wire.receive().unwrap().header.message,
            Message::Credit { .. }
        ));
        if case == "changed-replay" {
            wire.header.sequence = Some(1);
            wire.header.message = Message::ProofOriginalEnd {
                transfer_id: original_transfer_id,
                sha256: hex(&sha2::Sha256::digest(&replay)),
            };
            wire.send(Vec::new());
            assert!(matches!(
                wire.receive().unwrap().header.message,
                Message::Error { .. }
            ));
        } else if case == "cancel" {
            wire.header.request_id = 4;
            wire.header.operation_id = None;
            wire.header.stream_id = None;
            wire.header.sequence = None;
            wire.header.message = Message::Cancel { request_id: 3 };
            wire.send(Vec::new());
            assert!(matches!(
                wire.receive().unwrap().header.message,
                Message::Cancellation {
                    outcome: CancelOutcome::Unknown
                }
            ));
        } else {
            let old = wire.header.clone();
            wire.header.request_id = 4;
            wire.header.operation_id = None;
            wire.header.stream_id = None;
            wire.header.sequence = None;
            wire.header.message = Message::Release {
                lease_id: uuid([1; 16]),
                intent: ReleaseIntent::ViewDetachment,
            };
            wire.send(Vec::new());
            assert!(matches!(
                wire.receive().unwrap().header.message,
                Message::Ack {}
            ));
            wire.header.request_id = 5;
            wire.header.context = None;
            wire.header.message = Message::Register {
                lease_id: uuid([1; 16]),
                client_id: uuid([2; 16]),
                workspace_id: uuid([3; 16]),
                target_binding: wire.shared.binding.clone(),
                runtime_generation: wire.shared.runtime.clone(),
            };
            wire.send(Vec::new());
            assert!(matches!(
                wire.receive().unwrap().header.message,
                Message::Ack {}
            ));
            wire.header = old;
            wire.header.sequence = Some(1);
            wire.header.message = Message::ProofOriginalEnd {
                transfer_id: original_transfer_id,
                sha256: hex(&sha2::Sha256::digest(&body)),
            };
            wire.send(Vec::new());
            assert!(matches!(
                wire.receive().unwrap().header.message,
                Message::Error { .. }
            ));
        }
        assert_eq!(
            wire.shared
                .dispatcher
                .git
                .observation_storage_stats()
                .unwrap()
                .bytes,
            0,
            "{case} retained charged inputs"
        );
        assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 0);
        assert!(
            wire.shared
                .dispatcher
                .git
                .existing_receipt_sync(&wire.original)
                .unwrap()
                .is_none()
        );
    }
}
#[test]
fn lookup_disk_contention_and_unknown_preserve_original_history() {
    let mut wire = Wire::new(true);
    let receipt = wire
        .shared
        .dispatcher
        .git
        .mutate_sync(wire.original.clone(), &AtomicBool::new(false));
    assert!(matches!(receipt.state, OperationState::Confirmed(_)));
    let ledger = buntrail_services::operations::ledger::Ledger::open(
        wire._dir.path().join("state/operations"),
    )
    .unwrap();
    let lock = ledger.lock().unwrap();
    let body = wire.body();
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::Error { .. }
    ));
    wire.idle_counts();
    drop(lock);
    let mut record = ledger.read(wire.original.operation).unwrap().unwrap();
    record.receipt.state = OperationState::Unknown(ReconciliationEvidence {
        target: wire.original.worktree.target.clone(),
        observed: ObservedState::Unobserved,
        explanation: "accepted historical operation cannot replay".into(),
    });
    ledger.write(&record).unwrap();
    let path = ledger
        .directory
        .join(format!("{}.json", hex(&wire.original.operation.0)));
    let durable = std::fs::read(&path).unwrap();
    wire.header.request_id = 4;
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    let Message::ProofExisting { receipt } = wire.receive().unwrap().header.message else {
        panic!("Unknown receipt missing")
    };
    assert!(matches!(
        receipt
            .core(wire.shared.dispatcher.files.target())
            .unwrap()
            .state,
        OperationState::Unknown(_)
    ));
    assert_eq!(std::fs::read(path).unwrap(), durable);
}

#[test]
fn concurrent_acceptance_wins_before_invalid_proof_input_and_plan() {
    let mut wire = Wire::new(true);
    let body = wire.body();
    assert!(matches!(
        wire.begin(body.len() as u64).header.message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    let Message::ProofReady {
        original_transfer_id,
        approvals_transfer_id,
    } = wire.receive().unwrap().header.message
    else {
        panic!("promotion missing")
    };
    let expected = wire
        .shared
        .dispatcher
        .git
        .mutate_sync(wire.original.clone(), &AtomicBool::new(false));
    assert!(matches!(expected.state, OperationState::Confirmed(_)));
    wire.header.stream_id = Some(original_transfer_id.clone());
    wire.header.sequence = Some(0);
    wire.header.message = Message::ProofOriginalChunk {
        transfer_id: original_transfer_id.clone(),
        offset: 0,
    };
    wire.send(body.clone());
    wire.receive().unwrap();
    wire.header.sequence = Some(1);
    wire.header.message = Message::ProofOriginalEnd {
        transfer_id: original_transfer_id,
        sha256: hex(&sha2::Sha256::digest(body)),
    };
    wire.send(Vec::new());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::Ack {}
    ));
    wire.header.stream_id = Some(approvals_transfer_id.clone());
    wire.header.sequence = None;
    wire.header.message = Message::ProofApprovalsBegin {
        transfer_id: approvals_transfer_id.clone(),
        total_length: 96,
        proof_id: uuid([0; 16]),
        alias_digest: "00".repeat(32),
    };
    wire.send(Vec::new());
    wire.receive().unwrap();
    wire.header.sequence = Some(0);
    wire.header.message = Message::ProofApprovalsChunk {
        transfer_id: approvals_transfer_id.clone(),
        offset: 0,
    };
    wire.send(vec![0; 96]);
    wire.receive().unwrap();
    wire.header.sequence = Some(1);
    wire.header.message = Message::ProofApprovalsEnd {
        transfer_id: approvals_transfer_id,
        sha256: hex(&sha2::Sha256::digest([0; 96])),
    };
    wire.send(Vec::new());
    let Message::ProofExisting { receipt } = wire.receive().unwrap().header.message else {
        panic!("concurrent original acceptance lost")
    };
    assert_eq!(
        receipt.core(wire.shared.dispatcher.files.target()).unwrap(),
        expected
    );
    assert_eq!(
        wire.shared
            .dispatcher
            .git
            .observation_storage_stats()
            .unwrap()
            .bytes,
        0
    );
}
#[test]
fn complete_original_identity_wins_concurrent_cancel() {
    let mut wire = Wire::new(true);
    let expected = wire
        .shared
        .dispatcher
        .git
        .mutate_sync(wire.original.clone(), &AtomicBool::new(false));
    let body = wire.body();
    wire.begin(body.len() as u64);
    wire.original_chunks(&body);
    wire.end(&body);
    wire.header.request_id = 4;
    wire.header.operation_id = None;
    wire.header.stream_id = None;
    wire.header.sequence = None;
    wire.header.message = Message::Cancel { request_id: 3 };
    wire.send(Vec::new());
    let mut found = false;
    for _ in 0..2 {
        let response = wire.receive().unwrap();
        match response.header.message {
            Message::ProofExisting { receipt } => {
                assert_eq!(
                    receipt.core(wire.shared.dispatcher.files.target()).unwrap(),
                    expected
                );
                found = true;
            }
            Message::Cancellation {
                outcome: CancelOutcome::Unknown,
            } => {}
            other => panic!("unexpected concurrent cancellation result {other:?}"),
        }
    }
    assert!(found);
}
#[test]
fn expired_original_and_normal_replay_do_not_renew_on_incoming_bytes() {
    let wire = Wire::new(true);
    let body = wire.body();
    let (sender, incoming) = mpsc::sync_channel(1);
    let (consumed, _progress) = mpsc::sync_channel(1);
    let mut h = wire.header.clone();
    h.operation_id = Some(uuid(wire.original.operation.0));
    h.stream_id = Some(uuid([9; 16]));
    h.sequence = Some(0);
    h.message = Message::ProofLookupChunk {
        transfer_id: uuid([9; 16]),
        offset: 0,
    };
    sender
        .send(Frame {
            header: h.clone(),
            payload: body.clone(),
        })
        .unwrap();
    let expired = Instant::now() - Duration::from_secs(1);
    let reader = LookupReader {
        incoming,
        consumed,
        header: h.clone(),
        deadline: expired,
        buffer: Cursor::new(Vec::new()),
        verifier: TransferVerifier::new(uuid([9; 16]), body.len() as u64).unwrap(),
        sequence: 0,
        sealed: false,
    };
    assert!(
        proof_codec::hash_original(
            reader,
            body.len() as u64,
            wire.original.operation,
            wire.shared.dispatcher.files.target()
        )
        .is_err()
    );
    let identity = proof_codec::hash_original(
        body.as_slice(),
        body.len() as u64,
        wire.original.operation,
        wire.shared.dispatcher.files.target(),
    )
    .unwrap();
    h.sequence = None;
    h.message = Message::ProofLookupBegin {
        transfer_id: uuid([9; 16]),
        total_length: body.len() as u64,
        action: ProofAction::Prepare,
        lease_id: uuid([1; 16]),
    };
    let (mut normal, _) = promote(&wire.shared, &h, 1, identity).unwrap();
    normal.deadline = expired;
    let transfer = normal.header.stream_id.clone().unwrap();
    h.stream_id = Some(transfer.clone());
    h.sequence = Some(0);
    h.message = Message::ProofOriginalChunk {
        transfer_id: transfer,
        offset: 0,
    };
    assert!(
        normal
            .frame(
                &wire.shared,
                Frame {
                    header: h,
                    payload: body
                },
                &mut Vec::new(),
                None
            )
            .is_err()
    );
    assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        wire.shared
            .dispatcher
            .git
            .observation_storage_stats()
            .unwrap()
            .bytes,
        0
    );
}

#[test]
fn alias_transfer_id_collision_cannot_replace_another_workspace_upload() {
    let mut wire = Wire::new(true);
    let transfer = uuid([9; 16]);
    wire.header.stream_id = Some(transfer.clone());
    wire.header.message = Message::ProofObserveBegin {
        transfer_id: transfer.clone(),
        total_length: 8,
        lease_id: uuid([1; 16]),
        worktree: buntrail_protocol::services::Worktree::from_core(&wire.original.worktree)
            .unwrap(),
    };
    wire.send(Vec::new());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::Ack {}
    ));
    let victim = wire.header.clone();
    wire.header.request_id = 4;
    wire.header.stream_id = None;
    wire.header.context = None;
    wire.header.message = Message::Register {
        lease_id: uuid([4; 16]),
        client_id: uuid([2; 16]),
        workspace_id: uuid([4; 16]),
        target_binding: wire.shared.binding.clone(),
        runtime_generation: wire.shared.runtime.clone(),
    };
    wire.send(Vec::new());
    wire.receive().unwrap();
    wire.header.request_id = 5;
    wire.header.context = Some(Context {
        client_id: uuid([2; 16]),
        workspace_id: uuid([4; 16]),
        target_binding: wire.shared.binding.clone(),
        runtime_generation: wire.shared.runtime.clone(),
    });
    wire.header.stream_id = Some(transfer.clone());
    wire.header.message = Message::ProofObserveBegin {
        transfer_id: transfer.clone(),
        total_length: 8,
        lease_id: uuid([4; 16]),
        worktree: buntrail_protocol::services::Worktree::from_core(&wire.original.worktree)
            .unwrap(),
    };
    wire.send(Vec::new());
    assert!(
        matches!(
            wire.receive().unwrap().header.message,
            Message::Error { .. }
        ),
        "second workspace replaced the existing upload by reusing its transfer ID"
    );
    assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 1);
    wire.header = victim;
    wire.header.sequence = Some(0);
    wire.header.message = Message::ProofAliasesChunk {
        transfer_id: transfer.clone(),
        offset: 0,
    };
    let aliases = b"BTALIS01";
    wire.send(aliases.to_vec());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::Credit { .. }
    ));
    wire.header.sequence = Some(1);
    wire.header.message = Message::ProofAliasesEnd {
        transfer_id: transfer,
        sha256: hex(&sha2::Sha256::digest(aliases)),
    };
    wire.send(Vec::new());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::ProofOutputBegin { .. }
    ));
}

#[test]
fn wrong_file_messages_and_reserved_ids_cannot_consume_proof_uploads() {
    for attack in ["future-begin", "chunk", "end", "commit"] {
        let mut wire = Wire::new(true);
        let body = wire.body();
        wire.begin(body.len() as u64);
        wire.original_chunks(&body);
        wire.end(&body);
        let Message::ProofReady {
            original_transfer_id,
            approvals_transfer_id,
        } = wire.receive().unwrap().header.message
        else {
            panic!("promotion missing")
        };
        let mut original = wire.header.clone();
        original.stream_id = Some(original_transfer_id.clone());
        wire.header.request_id = 99;
        wire.header.sequence = None;
        wire.header.stream_id = Some(if attack == "future-begin" {
            approvals_transfer_id.clone()
        } else {
            original_transfer_id.clone()
        });
        wire.header.message = match attack {
            "future-begin" => Message::UploadBegin {
                transfer_id: approvals_transfer_id,
                total_length: 0,
                path_base64: STANDARD.encode(b"/unused"),
            },
            "chunk" => Message::UploadChunk {
                transfer_id: original_transfer_id.clone(),
                offset: 0,
            },
            "end" => Message::UploadEnd {
                transfer_id: original_transfer_id.clone(),
                sha256: "00".repeat(32),
            },
            _ => Message::SaveCommit {
                transfer_id: original_transfer_id.clone(),
                submitted_revision: 0,
                expected_version: None,
            },
        };
        wire.send(if attack == "chunk" {
            vec![1]
        } else {
            Vec::new()
        });
        assert!(
            matches!(
                wire.receive().unwrap().header.message,
                Message::Error { .. }
            ),
            "{attack} consumed another transfer"
        );
        wire.header = original;
        wire.header.sequence = Some(0);
        wire.header.message = Message::ProofOriginalChunk {
            transfer_id: original_transfer_id.clone(),
            offset: 0,
        };
        wire.send(body.clone());
        assert!(
            matches!(
                wire.receive().unwrap().header.message,
                Message::Credit { .. }
            ),
            "victim lost progress after {attack}"
        );
        wire.header.sequence = Some(1);
        wire.header.message = Message::ProofOriginalEnd {
            transfer_id: original_transfer_id,
            sha256: hex(&sha2::Sha256::digest(&body)),
        };
        wire.send(Vec::new());
        assert!(matches!(
            wire.receive().unwrap().header.message,
            Message::Ack {}
        ));
    }
}

#[test]
fn existing_only_missing_bypasses_all_normal_admission() {
    let mut wire = Wire::new(true);
    wire.original.command = GitMutation::Checkout {
        reference: vec![b'x'; 65536],
    };
    wire.shared.requests.store(8, Ordering::SeqCst);
    wire.shared.workers.store(4, Ordering::SeqCst);
    wire.shared
        .mutation_admission_closed
        .store(true, Ordering::SeqCst);
    let body = wire.body();
    assert!(body.len() > 65536);
    wire.header.operation_id = Some(uuid(wire.original.operation.0));
    wire.header.stream_id = Some(uuid([9; 16]));
    wire.header.message = Message::ProofLookupBegin {
        transfer_id: uuid([9; 16]),
        total_length: body.len() as u64,
        action: ProofAction::Lookup,
        lease_id: uuid([99; 16]),
    };
    wire.send(Vec::new());
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::ProofMissing {}
    ));
    wire.idle_counts();
    assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 8);
    assert_eq!(wire.shared.workers.load(Ordering::SeqCst), 4);
    assert_eq!(
        wire.shared
            .dispatcher
            .git
            .observation_storage_stats()
            .unwrap()
            .bytes,
        0
    );
    assert!(
        wire.shared
            .dispatcher
            .git
            .existing_receipt_sync(&wire.original)
            .unwrap()
            .is_none()
    );
    wire.shared.requests.store(0, Ordering::SeqCst);
    wire.shared.workers.store(0, Ordering::SeqCst);
}

#[test]
fn existing_only_all_seven_large_identities_preserve_missing_unknown_and_changed_payload() {
    let mut wire = Wire::new(true);
    let seed = wire
        .shared
        .dispatcher
        .git
        .mutate_sync(wire.original.clone(), &AtomicBool::new(false));
    assert!(matches!(seed.state, OperationState::Confirmed(_)));
    let ledger = buntrail_services::operations::ledger::Ledger::open(
        wire._dir.path().join("state/operations"),
    )
    .unwrap();
    let seed_operation = wire.original.operation;
    // Synthetic historical ledger identities exercise every opaque command without executing network commands.
    let commands = [
        GitMutation::Stage(vec![]),
        GitMutation::Unstage(vec![]),
        GitMutation::Commit {
            message: "test".into(),
        },
        GitMutation::Checkout {
            reference: vec![b'x'; 65536],
        },
        GitMutation::Fetch {
            remote: b"origin".to_vec(),
        },
        GitMutation::Push {
            remote: b"origin".to_vec(),
            reference: b"main".to_vec(),
        },
        GitMutation::PullFastForward {
            remote: b"origin".to_vec(),
            reference: b"main".to_vec(),
        },
    ];
    for (i, command) in commands.into_iter().enumerate() {
        wire.original.operation = OperationID([210 + i as u8; 16]);
        wire.original.command = command;
        wire.original.expected.head = GitHead::Unborn(vec![b'x'; 65536]);
        let body = wire.body();
        assert!(body.len() > 65536);
        wire.header.request_id += 1;
        wire.begin_action(body.len() as u64, ProofAction::Lookup);
        wire.original_chunks(&body);
        wire.end(&body);
        assert!(matches!(
            wire.receive().unwrap().header.message,
            Message::ProofMissing {}
        ));
        assert!(ledger.read(wire.original.operation).unwrap().is_none());
        let mut record = ledger.read(seed_operation).unwrap().unwrap();
        record.envelope.id = wire.original.operation;
        record.envelope.request_digest =
            sha2::Sha256::digest(serde_json::to_vec(&wire.original).unwrap()).into();
        record.receipt.id = wire.original.operation;
        record.receipt.state = OperationState::Unknown(ReconciliationEvidence {
            target: wire.original.worktree.target.clone(),
            observed: ObservedState::Unobserved,
            explanation: "fixture accepted original".into(),
        });
        ledger.write(&record).unwrap();
        let path = ledger
            .directory
            .join(format!("{}.json", hex(&wire.original.operation.0)));
        let bytes = std::fs::read(&path).unwrap();
        wire.header.request_id += 1;
        wire.begin_action(body.len() as u64, ProofAction::Lookup);
        wire.original_chunks(&body);
        wire.end(&body);
        let Message::ProofExisting { receipt } = wire.receive().unwrap().header.message else {
            panic!("historical original missing")
        };
        assert_eq!(
            receipt.core(wire.shared.dispatcher.files.target()).unwrap(),
            record.receipt
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        wire.original.expected.index_fingerprint[0] ^= 1;
        let changed = wire.body();
        wire.header.request_id += 1;
        wire.begin_action(changed.len() as u64, ProofAction::Lookup);
        wire.original_chunks(&changed);
        wire.end(&changed);
        assert!(matches!(
            wire.receive().unwrap().header.message,
            Message::Error { .. }
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        wire.idle_counts();
    }
}

#[test]
fn existing_only_capability_does_not_require_new_work_authority() {
    let mut wire = Wire::new(false);
    let body = wire.body();
    assert!(matches!(
        wire.begin_action(body.len() as u64, ProofAction::Lookup)
            .header
            .message,
        Message::ProofLookupReady { .. }
    ));
    wire.original_chunks(&body);
    wire.end(&body);
    assert!(matches!(
        wire.receive().unwrap().header.message,
        Message::ProofMissing {}
    ));
    assert_eq!(wire.shared.requests.load(Ordering::SeqCst), 0);
}
