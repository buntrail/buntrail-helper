use super::*;
use buntrail_services::git::proof_codec::{self, OriginalIdentity};

// One incoming frame and one consumed-credit notification per counted control worker.
pub(super) struct LookupReader {
    incoming: mpsc::Receiver<Frame>,
    consumed: mpsc::SyncSender<u32>,
    header: Header,
    deadline: Instant,
    buffer: Cursor<Vec<u8>>,
    verifier: TransferVerifier,
    sequence: u64,
    sealed: bool,
}
impl Read for LookupReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            if Instant::now() >= self.deadline {
                return Err(error("original transfer absolute deadline exceeded"));
            }
            let n = self.buffer.read(out)?;
            if n != 0 {
                return Ok(n);
            }
            if !self.buffer.get_ref().is_empty() {
                let bytes = self.buffer.get_ref().len() as u32;
                self.buffer = Cursor::new(Vec::new());
                self.consumed.try_send(bytes).map_err(error)?;
            }
            if self.sealed {
                return Ok(0);
            }
            let frame = self
                .incoming
                .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
                .map_err(error)?;
            let h = &frame.header;
            if h.context != self.header.context
                || h.operation_id != self.header.operation_id
                || h.request_id != self.header.request_id
                || h.stream_id != self.header.stream_id
                || h.sequence != Some(self.sequence)
            {
                return Err(error("original transfer owner or sequence mismatch"));
            }
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| error("original sequence overflow"))?;
            match &h.message {
                Message::ProofLookupChunk {
                    transfer_id,
                    offset,
                } => {
                    if frame.payload.is_empty() || frame.payload.len() > 65536 {
                        return Err(error("invalid original chunk"));
                    }
                    self.verifier
                        .chunk(transfer_id, *offset, &frame.payload)
                        .map_err(error)?;
                    self.buffer = Cursor::new(frame.payload);
                }
                Message::ProofLookupEnd {
                    transfer_id,
                    sha256,
                } if frame.payload.is_empty() => {
                    self.verifier
                        .end(transfer_id, unhex(sha256)?)
                        .map_err(error)?;
                    self.sealed = true;
                }
                _ => return Err(error("unexpected original frame type")),
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_original_requires_outer_seal_and_exact_sequence() {
        let (_, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
        let mut body = Vec::new();
        proof_codec::write_original(&mut body, &original, dispatcher.files.target()).unwrap();
        for malformed in [false, true] {
            let h = Header {
                major: 1,
                minor: 0,
                request_id: 77,
                context: None,
                operation_id: Some(uuid(original.operation.0)),
                stream_id: Some(uuid([9; 16])),
                sequence: None,
                message: Message::Ack {},
            };
            let (tx, rx) = mpsc::sync_channel(1);
            let (credit, credits) = mpsc::sync_channel(1);
            let bytes = body.clone();
            let header = h.clone();
            let sender = std::thread::spawn(move || {
                let mut f = reply(
                    &header,
                    Message::ProofLookupChunk {
                        transfer_id: uuid([9; 16]),
                        offset: 0,
                    },
                );
                f.header.sequence = Some(0);
                f.payload = bytes.clone();
                if tx.send(f).is_err() {
                    return;
                }
                if credits.recv_timeout(Duration::from_secs(2)).is_err() {
                    return;
                }
                let mut f = reply(
                    &header,
                    Message::ProofLookupEnd {
                        transfer_id: uuid([9; 16]),
                        sha256: hex(&sha2::Sha256::digest(bytes)),
                    },
                );
                f.header.sequence = Some(if malformed { 2 } else { 1 });
                let _ = tx.send(f);
            });
            let reader = LookupReader {
                incoming: rx,
                consumed: credit,
                header: h,
                deadline: Instant::now() + Duration::from_secs(5),
                buffer: Cursor::new(Vec::new()),
                verifier: TransferVerifier::new(uuid([9; 16]), body.len() as u64).unwrap(),
                sequence: 0,
                sealed: false,
            };
            let result = proof_codec::hash_original(
                reader,
                body.len() as u64,
                original.operation,
                dispatcher.files.target(),
            );
            sender.join().unwrap();
            if malformed {
                assert!(result.is_err());
            } else {
                assert!(
                    result.is_ok(),
                    "valid sealed original must reach target parser: {:?}",
                    result.err()
                );
            }
        }
    }
}

pub(super) struct Lookup {
    sender: Option<mpsc::SyncSender<Frame>>,
    progress: mpsc::Receiver<u32>,
    credit: usize,
    deadline: Instant,
}
pub enum Completed {
    Output(Output),
    Reply(Message),
    Lookup {
        identity: OriginalIdentity,
        receipt: Option<OperationReceipt>,
    },
}
pub(super) fn begin_lookup(
    shared: &Arc<Shared>,
    pending: &mut Vec<Pending>,
    h: &Header,
) -> io::Result<Option<Frame>> {
    let Message::ProofLookupBegin {
        transfer_id,
        total_length,
        ..
    } = &h.message
    else {
        return Err(error("lookup begin required"));
    };
    if pending.len() >= 12 || shared.controls.fetch_add(1, Ordering::SeqCst) >= 4 {
        if pending.len() < 12 {
            shared.controls.fetch_sub(1, Ordering::SeqCst);
        }
        return Ok(Some(admission_refusal(
            shared,
            h,
            ErrorCode::Unavailable,
            "original lookup control capacity reached",
        )?));
    }
    let guard = WorkGuard {
        shared: shared.clone(),
        control: true,
        service_kind: 0,
    };
    let (sender, incoming) = mpsc::sync_channel(1);
    let (consumed, progress) = mpsc::sync_channel(1);
    let deadline = Instant::now() + Duration::from_secs(120);
    let reader = LookupReader {
        incoming,
        consumed,
        header: h.clone(),
        deadline,
        buffer: Cursor::new(Vec::new()),
        verifier: TransferVerifier::new(transfer_id.clone(), *total_length).map_err(error)?,
        sequence: 0,
        sealed: false,
    };
    let operation = OperationID(id(h
        .operation_id
        .as_deref()
        .ok_or_else(|| error("original operation missing"))?)?);
    let length = *total_length;
    let state = shared.clone();
    let (tx, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let identity = proof_codec::hash_original(
                reader,
                length,
                operation,
                state.dispatcher.files.target(),
            )?;
            if Instant::now() >= deadline {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "original lookup deadline exceeded",
                ));
            }
            let receipt = state.dispatcher.git.existing_receipt_digest_sync(
                identity.operation(),
                state.dispatcher.files.target(),
                identity.digest(),
            )?;
            if Instant::now() >= deadline {
                return Err(CoreError::new(
                    ErrorCode::Unavailable,
                    "original lookup deadline exceeded",
                ));
            }
            Ok(Response::Proof(Box::new(Completed::Lookup {
                identity,
                receipt,
            })))
        })();
        let _ = tx.send((result, guard));
    });
    pending.push(Pending {
        header: h.clone(),
        receiver,
        cancelled: false,
        cancel: Arc::new(AtomicBool::new(false)),
        mutation: true,
        lookup: Some(Lookup {
            sender: Some(sender),
            progress,
            credit: 65536,
            deadline,
        }),
    });
    Ok(Some(reply(h, Message::ProofLookupReady { credit: 65536 })))
}

#[cfg(test)]
mod lookup_tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};
    #[test]
    fn original_receipt_lookup_uses_controls_before_normal_admission() {
        let (_dir, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
        let expected = dispatcher
            .git
            .mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(expected.state, OperationState::Confirmed(_)));
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: _dir.path().into(),
            dispatcher: Arc::new(dispatcher),
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            runtime: uuid([1; 16]),
            binding: "fixture".into(),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(4),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(8),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(true),
        });
        let mut bytes = Vec::new();
        proof_codec::write_original(&mut bytes, &original, shared.dispatcher.files.target())
            .unwrap();
        let mut h = Header {
            major: 1,
            minor: 0,
            request_id: 77,
            context: None,
            operation_id: Some(uuid(original.operation.0)),
            stream_id: Some(uuid([9; 16])),
            sequence: None,
            message: Message::ProofLookupBegin {
                transfer_id: uuid([9; 16]),
                total_length: bytes.len() as u64,
                action: ProofAction::Prepare,
                lease_id: uuid([8; 16]),
            },
        };
        let mut pending = vec![];
        let ready = begin_lookup(&shared, &mut pending, &h).unwrap().unwrap();
        assert!(
            matches!(
                ready.header.message,
                Message::ProofLookupReady { credit: 65536 }
            ),
            "normal saturation or paused maintenance must not block original lookup"
        );
        assert_eq!(shared.controls.load(Ordering::SeqCst), 1);
        h.sequence = Some(0);
        h.message = Message::ProofLookupChunk {
            transfer_id: uuid([9; 16]),
            offset: 0,
        };
        pending[0]
            .lookup
            .as_ref()
            .unwrap()
            .sender
            .as_ref()
            .unwrap()
            .send(Frame {
                header: h.clone(),
                payload: bytes.clone(),
            })
            .unwrap();
        assert_eq!(
            pending[0]
                .lookup
                .as_ref()
                .unwrap()
                .progress
                .recv_timeout(Duration::from_secs(3))
                .unwrap(),
            bytes.len() as u32
        );
        h.sequence = Some(1);
        h.message = Message::ProofLookupEnd {
            transfer_id: uuid([9; 16]),
            sha256: hex(&sha2::Sha256::digest(bytes)),
        };
        pending[0]
            .lookup
            .as_ref()
            .unwrap()
            .sender
            .as_ref()
            .unwrap()
            .send(Frame {
                header: h,
                payload: vec![],
            })
            .unwrap();
        let (result, guard) = pending[0]
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        let Response::Proof(value) = result.unwrap() else {
            panic!("lookup completion missing")
        };
        let Completed::Lookup { receipt, .. } = *value else {
            panic!("wrong result")
        };
        assert_eq!(receipt, Some(expected));
        drop(guard);
        drop(pending);
        assert_eq!(shared.controls.load(Ordering::SeqCst), 0);
    }
}

use buntrail_services::git::{
    observation::{
        ObservationInput, ObservationInputReader, ObservationInputWriter, ObservationOwner,
    },
    proof_codec::{
        AliasReader, TargetPathLimit,
        output::{EntryGroup, ObservationEvent, OutputWriter, OwnedObservation},
    },
    worktree_proof::WorktreePreparation,
};

pub(super) struct Normal {
    pub header: Header,
    owner: ObservationOwner,
    stage: Option<Stage>,
    writer: Option<ObservationInputWriter>,
    verifier: TransferVerifier,
    sequence: u64,
    pub credit: usize,
    deadline: Instant,
    guard: WorkGuard,
}
enum Stage {
    Aliases(WorktreeIdentity),
    Original {
        identity: OriginalIdentity,
        action: ProofAction,
        approvals: ObservationInputWriter,
        approvals_id: String,
    },
    AwaitApprovals {
        identity: OriginalIdentity,
        action: ProofAction,
        original: Box<ObservationInput>,
        approvals: ObservationInputWriter,
        approvals_id: String,
    },
    Approvals {
        identity: OriginalIdentity,
        action: ProofAction,
        original: ObservationInput,
        proof_id: [u8; 16],
        alias_digest: [u8; 32],
    },
}
fn unavailable(message: &str) -> CoreError {
    CoreError::new(ErrorCode::Unavailable, message)
}
fn owner(
    shared: &Shared,
    h: &Header,
    serial: u64,
    lease: &str,
) -> Result<ObservationOwner, CoreError> {
    shared.dispatcher.observation_owner(
        &*shared
            .leases
            .lock()
            .map_err(|_| unavailable("lease lock failed"))?,
        lease,
        h.context
            .as_ref()
            .ok_or_else(|| unavailable("missing owner context"))?,
        serial,
    )
}
fn normal_guard(shared: &Arc<Shared>) -> Result<WorkGuard, CoreError> {
    if shared.requests.fetch_add(1, Ordering::SeqCst) >= 8 {
        shared.requests.fetch_sub(1, Ordering::SeqCst);
        return Err(unavailable("normal proof work capacity reached"));
    }
    Ok(WorkGuard {
        shared: shared.clone(),
        control: false,
        service_kind: 1,
    })
}
pub(super) fn promote(
    shared: &Arc<Shared>,
    h: &Header,
    serial: u64,
    identity: OriginalIdentity,
) -> Result<(Box<Normal>, Frame), CoreError> {
    let Message::ProofLookupBegin {
        lease_id, action, ..
    } = &h.message
    else {
        return Err(unavailable("lookup metadata missing"));
    };
    let guard = normal_guard(shared)?;
    if shared.mutation_admission_closed.load(Ordering::SeqCst) {
        return Err(unavailable("mutation admission paused"));
    }
    let owner = owner(shared, h, serial, lease_id)?;
    let (original, approvals) = shared.dispatcher.git.observation_input_pair(&owner)?;
    let original_id = uuid(new_id()?);
    let approvals_id = uuid(new_id()?);
    let mut header = h.clone();
    header.stream_id = Some(original_id.clone());
    header.sequence = None;
    let verifier = TransferVerifier::new(original_id.clone(), identity.length())
        .map_err(|_| unavailable("invalid original length"))?;
    let ready = reply(
        h,
        Message::ProofReady {
            original_transfer_id: original_id,
            approvals_transfer_id: approvals_id.clone(),
        },
    );
    Ok((
        Box::new(Normal {
            header,
            owner,
            stage: Some(Stage::Original {
                identity,
                action: action.clone(),
                approvals,
                approvals_id,
            }),
            writer: Some(original),
            verifier,
            sequence: 0,
            credit: 65536,
            deadline: Instant::now() + Duration::from_secs(120),
            guard,
        }),
        ready,
    ))
}
pub(super) fn observe(
    shared: &Arc<Shared>,
    h: &Header,
    serial: u64,
) -> Result<Box<Normal>, CoreError> {
    let Message::ProofObserveBegin {
        lease_id,
        worktree,
        transfer_id,
        total_length,
    } = &h.message
    else {
        return Err(unavailable("observe metadata missing"));
    };
    let guard = normal_guard(shared)?;
    let owner = owner(shared, h, serial, lease_id)?;
    let worktree = worktree.core(shared.dispatcher.files.target())?;
    let writer = shared.dispatcher.git.observation_input(&owner)?;
    Ok(Box::new(Normal {
        header: h.clone(),
        owner,
        stage: Some(Stage::Aliases(worktree)),
        writer: Some(writer),
        verifier: TransferVerifier::new(transfer_id.clone(), *total_length)
            .map_err(|_| unavailable("invalid aliases length"))?,
        sequence: 0,
        credit: 65536,
        deadline: Instant::now() + Duration::from_secs(120),
        guard,
    }))
}
impl Normal {
    pub fn current(&self) -> bool {
        self.owner.is_active() && Instant::now() < self.deadline
    }
    pub fn reserved_transfer(&self) -> Option<&str> {
        match &self.stage {
            Some(
                Stage::Original { approvals_id, .. } | Stage::AwaitApprovals { approvals_id, .. },
            ) => Some(approvals_id),
            _ => None,
        }
    }
    pub fn accepts(&self, h: &Header) -> bool {
        self.header.request_id == h.request_id
            && self.header.context == h.context
            && self.header.operation_id == h.operation_id
            && match &self.stage {
                Some(Stage::AwaitApprovals { approvals_id, .. }) => {
                    matches!(&h.message,Message::ProofApprovalsBegin { transfer_id,.. } if transfer_id==approvals_id)
                }
                _ => self.header.stream_id == h.stream_id,
            }
    }
    pub fn frame(
        mut self: Box<Self>,
        shared: &Arc<Shared>,
        frame: Frame,
        pending: &mut Vec<Pending>,
        authentication: Option<std::ffi::OsString>,
        repository_capability: bool,
    ) -> Result<Option<(Box<Self>, Frame)>, CoreError> {
        if !self.current() || !self.accepts(&frame.header) {
            return Err(unavailable("proof transfer owner expired or changed"));
        }
        let h = &frame.header;
        if let Message::ProofApprovalsBegin {
            transfer_id,
            total_length,
            proof_id,
            alias_digest,
        } = &h.message
        {
            let Some(Stage::AwaitApprovals {
                identity,
                action,
                original,
                approvals,
                approvals_id,
            }) = self.stage.take()
            else {
                return Err(unavailable("approvals before original seal"));
            };
            if transfer_id != &approvals_id || total_length % 96 != 0 {
                return Err(unavailable("invalid approval length or transfer"));
            }
            self.writer = Some(approvals);
            self.header.stream_id = Some(approvals_id);
            self.sequence = 0;
            self.credit = 65536;
            self.verifier = TransferVerifier::new(transfer_id.clone(), *total_length)
                .map_err(|_| unavailable("invalid approval transfer"))?;
            self.stage = Some(Stage::Approvals {
                identity,
                action,
                original: *original,
                proof_id: id(proof_id).map_err(error_core)?,
                alias_digest: unhex(alias_digest).map_err(error_core)?,
            });
            return Ok(Some((self, reply(h, Message::Ack {}))));
        }
        if h.sequence != Some(self.sequence) {
            return Err(unavailable("proof transfer sequence mismatch"));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| unavailable("proof sequence overflow"))?;
        let (transfer, offset) = match (&self.stage, &h.message) {
            (
                Some(Stage::Aliases(_)),
                Message::ProofAliasesChunk {
                    transfer_id,
                    offset,
                },
            )
            | (
                Some(Stage::Original { .. }),
                Message::ProofOriginalChunk {
                    transfer_id,
                    offset,
                },
            )
            | (
                Some(Stage::Approvals { .. }),
                Message::ProofApprovalsChunk {
                    transfer_id,
                    offset,
                },
            ) => (transfer_id.as_str(), Some(*offset)),
            _ => ("", None),
        };
        if let Some(offset) = offset {
            if frame.payload.is_empty() || frame.payload.len() > self.credit {
                return Err(unavailable("proof credit exhausted"));
            }
            self.credit -= frame.payload.len();
            self.verifier
                .chunk(transfer, offset, &frame.payload)
                .map_err(error_core)?;
            self.writer
                .as_mut()
                .ok_or_else(|| unavailable("proof writer missing"))?
                .append(&frame.payload)?;
            let mut credit = reply(
                h,
                Message::Credit {
                    bytes: frame.payload.len() as u32,
                },
            );
            credit.header.sequence = None;
            return Ok(Some((self, credit)));
        }
        let (transfer, sha) = match (&self.stage, &h.message) {
            (
                Some(Stage::Aliases(_)),
                Message::ProofAliasesEnd {
                    transfer_id,
                    sha256,
                },
            )
            | (
                Some(Stage::Original { .. }),
                Message::ProofOriginalEnd {
                    transfer_id,
                    sha256,
                },
            )
            | (
                Some(Stage::Approvals { .. }),
                Message::ProofApprovalsEnd {
                    transfer_id,
                    sha256,
                },
            ) => (transfer_id, sha256),
            _ => return Err(unavailable("proof record type or phase mismatch")),
        };
        if !frame.payload.is_empty() {
            return Err(unavailable("proof end payload"));
        }
        let digest = unhex(sha).map_err(error_core)?;
        self.verifier.end(transfer, digest).map_err(error_core)?;
        let input = self
            .writer
            .take()
            .ok_or_else(|| unavailable("proof writer missing"))?
            .seal()?;
        let stage = self
            .stage
            .take()
            .ok_or_else(|| unavailable("proof stage missing"))?;
        if let Stage::Original {
            identity,
            action,
            approvals,
            approvals_id,
        } = stage
        {
            if input.len() != identity.length() || digest != identity.wire_digest() {
                return Err(unavailable(
                    "original replay differs from authenticated lookup",
                ));
            }
            self.stage = Some(Stage::AwaitApprovals {
                identity,
                action,
                original: Box::new(input),
                approvals,
                approvals_id,
            });
            return Ok(Some((self, reply(h, Message::Ack {}))));
        }
        let state = shared.clone();
        let owner = self.owner;
        let header = self.header;
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (tx, receiver) = mpsc::sync_channel(1);
        let guard = self.guard;
        let mutation = matches!(stage, Stage::Approvals { .. });
        std::thread::spawn(move || {
            let result =
                buntrail_services::git::authentication::with_authentication(authentication, || {
                    match stage {
                        Stage::Aliases(worktree) => {
                            build_output(&state, &owner, worktree, input, &worker_cancel)
                                .map(|out| Response::Proof(Box::new(Completed::Output(out))))
                        }
                        Stage::Approvals {
                            identity,
                            action,
                            original,
                            proof_id,
                            alias_digest,
                        } => {
                            let request = proof_codec::read_original(
                                original.reader()?,
                                &identity,
                                state.dispatcher.files.target(),
                            )?;
                            if matches!(request.command, GitMutation::Repository(_))
                                && !repository_capability
                            {
                                return Err(unavailable(
                                    "Repository capability was not negotiated",
                                ));
                            }
                            drop(original);
                            let message = match action {
                                ProofAction::Lookup => {
                                    return Err(unavailable("lookup cannot be promoted"));
                                }
                                ProofAction::Prepare => match state
                                    .dispatcher
                                    .git
                                    .prepare_worktree_sync(
                                        &owner,
                                        &request,
                                        proof_id,
                                        alias_digest,
                                        input,
                                        &worker_cancel,
                                    )? {
                                    WorktreePreparation::Existing(receipt) => {
                                        Message::ProofExisting {
                                            receipt:
                                                buntrail_protocol::services::Receipt::from_core(
                                                    &receipt,
                                                )?,
                                        }
                                    }
                                    WorktreePreparation::Prepared(plan) => Message::ProofPrepared {
                                        plan_id: uuid(plan),
                                    },
                                },
                                ProofAction::Execute => Message::ProofExisting {
                                    receipt: buntrail_protocol::services::Receipt::from_core(
                                        &state.dispatcher.git.execute_worktree_sync(
                                            &owner,
                                            request,
                                            proof_id,
                                            alias_digest,
                                            input,
                                            &worker_cancel,
                                        )?,
                                    )?,
                                },
                            };
                            Ok(Response::Proof(Box::new(Completed::Reply(message))))
                        }
                        _ => Err(unavailable("incomplete proof transfer")),
                    }
                });
            let _ = tx.send((result, guard));
        });
        pending.push(Pending {
            header,
            receiver,
            cancelled: false,
            cancel,
            mutation,
            lookup: None,
        });
        Ok(None)
    }
}
fn error_core(e: impl std::fmt::Display) -> CoreError {
    CoreError::new(ErrorCode::InvalidArgument, &e.to_string())
}

pub struct Output {
    shared: Arc<Shared>,
    owner: ObservationOwner,
    observation: [u8; 16],
    delivered: bool,
    input: Option<ObservationInput>,
    reader: Option<ObservationInputReader>,
    pub length: u64,
    pub digest: String,
    pub offset: u64,
    pub sequence: u64,
    deadline: Instant,
}
struct HashOutput<W> {
    writer: W,
    hash: sha2::Sha256,
}
impl<W: Write> Write for HashOutput<W> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let n = self.writer.write(b)?;
        self.hash.update(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}
fn build_output(
    shared: &Arc<Shared>,
    owner: &ObservationOwner,
    worktree: WorktreeIdentity,
    input: ObservationInput,
    cancel: &AtomicBool,
) -> Result<Output, CoreError> {
    let limit = TargetPathLimit::declared(libc::PATH_MAX as u32)?;
    let aliases = AliasReader::new(
        input.reader()?,
        input.len(),
        shared.dispatcher.files.target(),
        limit,
    )?;
    let retained = shared
        .dispatcher
        .git
        .observe_captured_sync(owner, worktree, aliases, cancel)?;
    drop(input);
    let result = (|| {
        let alias_digest = shared
            .dispatcher
            .git
            .observation_alias_digest(owner, retained.id)?;
        let summary = OwnedObservation {
            id: retained.id,
            worktree: retained.snapshot.worktree,
            state: retained.snapshot.state,
            alias_digest,
            retained_bytes: retained.bytes,
        };
        let storage = shared.dispatcher.git.observation_input(owner)?;
        let mut output = OutputWriter::new(
            HashOutput {
                writer: std::io::BufWriter::with_capacity(65536, storage),
                hash: sha2::Sha256::new(),
            },
            &summary,
            limit,
        )?;
        for (group, entries) in [
            (EntryGroup::Staged, retained.snapshot.staged),
            (EntryGroup::Unstaged, retained.snapshot.unstaged),
            (EntryGroup::Untracked, retained.snapshot.untracked),
            (EntryGroup::Conflict, retained.snapshot.conflicts),
        ] {
            for entry in entries {
                if cancel.load(Ordering::SeqCst) {
                    return Err(unavailable("observation delivery cancelled"));
                }
                output.event(&ObservationEvent::Entry { group, entry })?;
            }
        }
        let mut original = shared
            .dispatcher
            .git
            .observation_reader(owner, retained.id)?;
        while let Some(record) = original.next_record()? {
            if record.membership.is_some() {
                output.event(&ObservationEvent::Alias(record))?;
            }
        }
        drop(original);
        let mut output = output.finish()?;
        output.flush().map_err(error_core)?;
        let digest = hex(&output.hash.finalize());
        let input = output.writer.into_inner().map_err(error_core)?.seal()?;
        Ok(Output {
            shared: shared.clone(),
            owner: owner.clone(),
            observation: retained.id,
            delivered: false,
            length: input.len(),
            reader: Some(input.reader()?),
            input: Some(input),
            digest,
            offset: 0,
            sequence: 0,
            deadline: Instant::now() + Duration::from_secs(120),
        })
    })();
    if result.is_err() {
        shared
            .dispatcher
            .git
            .release_observation(owner, retained.id);
    }
    result
}
impl Output {
    pub fn next(&mut self, h: &Header, credit: &mut usize) -> io::Result<Option<Frame>> {
        if Instant::now() >= self.deadline {
            return Err(error("proof output deadline exceeded"));
        }
        if self.offset == self.length {
            self.reader = None;
            self.input = None;
            self.delivered = true;
            let mut frame = reply(
                h,
                Message::ProofOutputEnd {
                    transfer_id: h.stream_id.clone().unwrap(),
                    sha256: self.digest.clone(),
                },
            );
            frame.header.sequence = Some(self.sequence);
            return Ok(Some(frame));
        }
        if *credit == 0 {
            return Ok(None);
        }
        let mut payload = vec![
            0;
            (*credit)
                .min(65536)
                .min((self.length - self.offset) as usize)
        ];
        self.reader
            .as_mut()
            .ok_or_else(|| error("proof output closed"))?
            .read_exact(&mut payload)?;
        let mut frame = reply(
            h,
            Message::ProofOutputChunk {
                transfer_id: h.stream_id.clone().unwrap(),
                offset: self.offset,
            },
        );
        frame.header.sequence = Some(self.sequence);
        self.sequence += 1;
        self.offset += payload.len() as u64;
        *credit -= payload.len();
        frame.payload = payload;
        Ok(Some(frame))
    }
}

pub(super) fn is_message(message: &Message) -> bool {
    matches!(
        message,
        Message::ProofLookupBegin { .. }
            | Message::ProofLookupReady { .. }
            | Message::ProofLookupChunk { .. }
            | Message::ProofLookupEnd { .. }
            | Message::ProofReady { .. }
            | Message::ProofObserveBegin { .. }
            | Message::ProofOriginalChunk { .. }
            | Message::ProofOriginalEnd { .. }
            | Message::ProofApprovalsBegin { .. }
            | Message::ProofApprovalsChunk { .. }
            | Message::ProofApprovalsEnd { .. }
            | Message::ProofAliasesChunk { .. }
            | Message::ProofAliasesEnd { .. }
            | Message::ProofOutputBegin { .. }
            | Message::ProofOutputChunk { .. }
            | Message::ProofOutputEnd { .. }
            | Message::ProofPrepared { .. }
            | Message::ProofExisting { .. }
            | Message::ProofMissing { .. }
            | Message::ProofCancel { .. }
            | Message::ProofRelease { .. }
    )
}
pub(super) fn lookup_frame(h: &Header) -> bool {
    matches!(
        h.message,
        Message::ProofLookupChunk { .. } | Message::ProofLookupEnd { .. }
    )
}
impl Lookup {
    pub fn cancel(&mut self) {
        self.sender = None;
    }
}
pub(super) fn receive_lookup(pending: &mut [Pending], frame: Frame) -> io::Result<()> {
    let p = pending
        .iter_mut()
        .find(|p| {
            p.header.request_id == frame.header.request_id
                && p.header.context == frame.header.context
                && p.header.operation_id == frame.header.operation_id
                && p.header.stream_id == frame.header.stream_id
        })
        .ok_or_else(|| error("original transfer owner missing"))?;
    let lookup = p
        .lookup
        .as_mut()
        .ok_or_else(|| error("original transfer phase missing"))?;
    if Instant::now() >= lookup.deadline || frame.payload.len() > lookup.credit {
        lookup.cancel();
        return Err(error("original deadline or credit exceeded"));
    }
    lookup.credit -= frame.payload.len();
    let ended = matches!(frame.header.message, Message::ProofLookupEnd { .. });
    lookup
        .sender
        .as_ref()
        .ok_or_else(|| error("original transfer already ended"))?
        .try_send(frame)
        .map_err(error)?;
    if ended {
        lookup.sender = None;
    }
    Ok(())
}
pub(super) fn poll_lookups(
    pending: &mut [Pending],
    output: &mut VecDeque<Frame>,
) -> io::Result<()> {
    for p in pending {
        if let Some(lookup) = &mut p.lookup {
            if Instant::now() >= lookup.deadline {
                lookup.cancel();
            }
            if output.len() < 31
                && let Ok(bytes) = lookup.progress.try_recv()
            {
                let mut frame = reply(&p.header, Message::Credit { bytes });
                frame.header.sequence = None;
                output.push_back(frame);
            }
        }
    }
    Ok(())
}
pub(super) fn cleanup(
    shared: &Arc<Shared>,
    pending: &mut Vec<Pending>,
    h: &Header,
    serial: u64,
) -> io::Result<Option<Frame>> {
    if pending.len() >= 12 || shared.controls.fetch_add(1, Ordering::SeqCst) >= 4 {
        if pending.len() < 12 {
            shared.controls.fetch_sub(1, Ordering::SeqCst);
        }
        return Ok(Some(admission_refusal(
            shared,
            h,
            ErrorCode::Unavailable,
            "proof cleanup control capacity reached",
        )?));
    }
    let guard = WorkGuard {
        shared: shared.clone(),
        control: true,
        service_kind: 0,
    };
    let state = shared.clone();
    let header = h.clone();
    let (tx, receiver) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = (|| {
            let lease = match &header.message {
                Message::ProofCancel { lease_id, .. } | Message::ProofRelease { lease_id, .. } => {
                    lease_id
                }
                _ => return Err(unavailable("cleanup type")),
            };
            let owner = owner(&state, &header, serial, lease)?;
            match &header.message {
                Message::ProofCancel { plan_id, .. } => state
                    .dispatcher
                    .git
                    .cancel_worktree_plan(&owner, id(plan_id).map_err(error_core)?),
                Message::ProofRelease { observation_id, .. } => state
                    .dispatcher
                    .git
                    .release_observation(&owner, id(observation_id).map_err(error_core)?),
                _ => unreachable!(),
            }
            Ok(Response::Proof(Box::new(Completed::Reply(Message::Ack {}))))
        })();
        let _ = tx.send((result, guard));
    });
    pending.push(Pending {
        header: h.clone(),
        receiver,
        cancelled: false,
        cancel: Arc::new(AtomicBool::new(false)),
        mutation: false,
        lookup: None,
    });
    Ok(None)
}

pub(super) fn issued_credit(pending: &mut [Pending], h: &Header, bytes: u32) -> io::Result<()> {
    if let Some(p) = pending.iter_mut().find(|p| {
        p.header.request_id == h.request_id
            && p.header.context == h.context
            && p.header.stream_id == h.stream_id
    }) && let Some(lookup) = &mut p.lookup
    {
        lookup.credit = lookup
            .credit
            .checked_add(bytes as usize)
            .filter(|n| *n <= 65536)
            .ok_or_else(|| error("original credit overflow"))?;
    }
    Ok(())
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};
    #[test]
    fn abandoned_output_retires_original_after_closing_owned_descriptors() {
        let (dir, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
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
        let context = Context {
            client_id: uuid([1; 16]),
            workspace_id: uuid([2; 16]),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        };
        let lease = uuid([3; 16]);
        shared
            .leases
            .lock()
            .unwrap()
            .register(lease.clone(), context.clone(), 1)
            .unwrap();
        let owner = shared
            .dispatcher
            .observation_owner(&shared.leases.lock().unwrap(), &lease, &context, 1)
            .unwrap();
        let mut input = shared.dispatcher.git.observation_input(&owner).unwrap();
        proof_codec::write_aliases(
            &mut input,
            shared.dispatcher.files.target(),
            std::iter::empty(),
        )
        .unwrap();
        let output = build_output(
            &shared,
            &owner,
            original.worktree,
            input.seal().unwrap(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(
            shared
                .dispatcher
                .git
                .observation_storage_stats()
                .unwrap()
                .bytes
                > 0
        );
        drop(output);
        assert_eq!(
            shared
                .dispatcher
                .git
                .observation_storage_stats()
                .unwrap()
                .bytes,
            0,
            "cancelled delivery retained its original observation"
        );
    }
}

impl Drop for Output {
    fn drop(&mut self) {
        self.reader = None;
        self.input = None;
        if !self.delivered {
            self.shared
                .dispatcher
                .git
                .release_observation(&self.owner, self.observation);
        }
    }
}

#[cfg(test)]
mod wire_tests;
