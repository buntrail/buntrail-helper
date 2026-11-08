pub(crate) mod proof;
use crate::framed::dispatcher::{Request, Response};
use crate::framed::supervisor::{Shared, error, hex, id, uuid};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use buntrail_core::contracts::async_types::EventStream;
use buntrail_core::contracts::*;
use buntrail_protocol::services::{Call, Reply};
use buntrail_protocol::{
    frame::{Decoder, Frame, TransferVerifier},
    negotiation::{INITIAL_CREDIT, Negotiated},
    types::*,
};
use buntrail_services::connections::local::new_id;
use sha2::Digest;
use std::{
    collections::{HashMap, VecDeque},
    fs::File,
    io::{self, Cursor, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::{Arc, atomic::Ordering, mpsc},
    time::{Duration, Instant},
};
use std::{
    sync::atomic::AtomicBool,
    task::{Context as TaskContext, Poll, Waker},
};
fn reply(h: &Header, message: Message) -> Frame {
    let mut header = h.clone();
    header.message = message;
    Frame {
        header,
        payload: vec![],
    }
}
fn observation(observed: ObservedState) -> WireObservation {
    match observed {
        ObservedState::File {
            file,
            version,
            digest,
        } => {
            let TargetPath::PosixBytes(path) = file.path else {
                return WireObservation::Unobserved;
            };
            WireObservation::File {
                path_base64: STANDARD.encode(path),
                version: version.as_ref().map(wire_version),
                digest: digest.as_ref().map(|d| hex(d)),
            }
        }
        _ => WireObservation::Unobserved,
    }
}
fn receipt(h: &Header, r: OperationReceipt) -> Frame {
    let mut saved_version = None;
    let mut saved_revision = None;
    let mut failure = None;
    let mut observed = WireObservation::Unobserved;
    let mut safe_message = String::new();
    let state = match r.state {
        OperationState::Accepted => ReceiptState::Accepted,
        OperationState::Running => ReceiptState::Running,
        OperationState::Confirmed(MutationResult::Saved(saved)) => {
            saved_version = Some(wire_version(&saved.version));
            saved_revision = Some(saved.saved_revision.0);
            ReceiptState::Confirmed
        }
        OperationState::Confirmed(_) => {
            return reply(
                h,
                Message::Error {
                    code: "unavailable".into(),
                    safe_message: "receipt kind requires an unavailable capability".into(),
                },
            );
        }
        OperationState::Failed(f) => {
            failure = Some(WireFailure {
                code: format!("{:?}", f.error.code),
                effect: match f.effect {
                    FailureEffect::ProvenNoEffect => WireEffect::ProvenNoEffect,
                    FailureEffect::PossiblePartialEffects => WireEffect::PossiblePartialEffects,
                },
            });
            safe_message = f.error.message;
            observed = observation(f.observed);
            ReceiptState::Failed
        }
        OperationState::Unknown(e) => {
            safe_message = e.explanation;
            observed = observation(e.observed);
            ReceiptState::Unknown
        }
    };
    reply(
        h,
        Message::Receipt {
            state,
            saved_version,
            saved_revision,
            safe_message,
            failure,
            observed,
        },
    )
}
fn wire_version(v: &FileVersion) -> WireVersion {
    WireVersion {
        opaque_token: STANDARD.encode(&v.opaque_token),
        content_digest: hex(&v.content_digest),
        file_identity: STANDARD.encode(&v.file_identity),
    }
}
struct WorkGuard {
    shared: Arc<Shared>,
    control: bool,
    service_kind: u8,
}
impl Drop for WorkGuard {
    fn drop(&mut self) {
        let count = if self.service_kind != 0 {
            service_count(&self.shared, self.service_kind)
        } else if self.control {
            &self.shared.controls
        } else {
            &self.shared.workers
        };
        count.fetch_sub(1, Ordering::SeqCst);
        self.shared.wake.notify();
    }
}
struct Pending {
    lookup: Option<proof::Lookup>,
    header: Header,
    receiver: mpsc::Receiver<(Result<Response, CoreError>, WorkGuard)>,
    cancelled: bool,
    cancel: Arc<AtomicBool>,
    mutation: bool,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if !self.mutation {
            self.cancel.store(true, Ordering::SeqCst);
        }
    }
}
fn service_count(shared: &Shared, kind: u8) -> &std::sync::atomic::AtomicUsize {
    match kind {
        2 => &shared.watchers,
        3 => &shared.searches,
        _ => &shared.requests,
    }
}
struct ServiceStream {
    proof: Option<proof::Output>,
    header: Header,
    source: Option<EventStream<Reply>>,
    bytes: Vec<u8>,
    offset: usize,
    credit: usize,
    sequence: u64,
    digest: String,
    terminal: bool,
    _guard: WorkGuard,
}
fn service_bytes(value: &Reply) -> io::Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            if self.0.len().saturating_add(b.len()) > 32 * 1024 * 1024 {
                return Err(error("service result exceeds 32 MiB"));
            }
            self.0.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = Bounded(Vec::new());
    if serde_json::to_writer(&mut output, value).is_err() {
        return serde_json::to_vec(&Reply::error(CoreError::new(
            ErrorCode::Unavailable,
            "Service result exceeds bounded transfer limit",
        )))
        .map_err(error);
    }
    Ok(output.0)
}
fn service_stream(
    header: &Header,
    guard: WorkGuard,
    value: Option<Reply>,
    source: Option<EventStream<Reply>>,
) -> io::Result<ServiceStream> {
    let bytes = value
        .as_ref()
        .map(service_bytes)
        .transpose()?
        .unwrap_or_default();
    let mut header = header.clone();
    header.stream_id = Some(uuid(new_id().map_err(error)?));
    Ok(ServiceStream {
        proof: None,
        header,
        terminal: source.is_none(),
        source,
        digest: hex(&sha2::Sha256::digest(&bytes)),
        bytes,
        offset: 0,
        credit: INITIAL_CREDIT,
        sequence: 0,
        _guard: guard,
    })
}
struct ReadStream {
    header: Header,
    source: Box<dyn Read + Send>,
    _snapshot: FileSnapshot,
    _guard: WorkGuard,
    offset: u64,
    ended: bool,
    credit: usize,
}
struct FileUpload {
    owner: Context,
    credit: usize,
    staging: tempfile::NamedTempFile,
    file: FileRef,
    operation: OperationID,
    verifier: TransferVerifier,
    digest: Option<[u8; 32]>,
    length: u64,
    touched: Instant,
    request_id: u64,
}
enum Upload {
    File(Box<FileUpload>),
    Proof(Box<proof::Normal>),
}
impl Upload {
    fn owner(&self) -> &Context {
        match self {
            Self::File(u) => &u.owner,
            Self::Proof(u) => u.header.context.as_ref().unwrap(),
        }
    }
    fn request_id(&self) -> u64 {
        match self {
            Self::File(u) => u.request_id,
            Self::Proof(u) => u.header.request_id,
        }
    }
    fn credit_mut(&mut self) -> &mut usize {
        match self {
            Self::File(u) => &mut u.credit,
            Self::Proof(u) => &mut u.credit,
        }
    }
    fn current(&self) -> bool {
        match self {
            Self::File(u) => u.touched.elapsed() < Duration::from_secs(600),
            Self::Proof(u) => u.current(),
        }
    }
    fn grant_credit(&mut self, h: &Header, bytes: u32) -> io::Result<()> {
        let owned = match &*self {
            Self::File(u) => {
                h.request_id == u.request_id
                    && h.context.as_ref() == Some(&u.owner)
                    && h.operation_id.as_deref() == Some(&uuid(u.operation.0))
            }
            Self::Proof(u) => {
                h.request_id == u.header.request_id
                    && h.context == u.header.context
                    && h.operation_id == u.header.operation_id
                    && h.stream_id == u.header.stream_id
            }
        };
        if owned {
            let maximum = if matches!(self, Self::Proof(_)) {
                65536
            } else {
                INITIAL_CREDIT
            };
            let credit = self.credit_mut();
            *credit = credit
                .checked_add(bytes as usize)
                .filter(|n| *n <= maximum)
                .ok_or_else(|| error("upload credit overflow"))?;
        }
        Ok(())
    }
}
fn transfer_in_use(uploads: &HashMap<String, Upload>, id: &str) -> bool {
    uploads.contains_key(id)
        || uploads
            .values()
            .any(|u| matches!(u, Upload::Proof(p) if p.reserved_transfer() == Some(id)))
}
fn insert_proof_upload(
    uploads: &mut HashMap<String, Upload>,
    normal: Box<proof::Normal>,
) -> Result<(), CoreError> {
    let id = normal.header.stream_id.as_ref().unwrap();
    if transfer_in_use(uploads, id)
        || normal
            .reserved_transfer()
            .is_some_and(|future| future == id || transfer_in_use(uploads, future))
    {
        return Err(CoreError::new(
            ErrorCode::Unavailable,
            "proof transfer ID already reserved",
        ));
    }
    uploads.insert(id.clone(), Upload::Proof(normal));
    Ok(())
}
fn file_phase_targets_proof(uploads: &HashMap<String, Upload>, h: &Header) -> bool {
    let id = match &h.message {
        Message::UploadChunk { transfer_id, .. }
        | Message::UploadEnd { transfer_id, .. }
        | Message::CreateCommit { transfer_id }
        | Message::SaveCommit { transfer_id, .. }
        | Message::SaveCommitOwned { transfer_id, .. } => transfer_id,
        _ => return false,
    };
    matches!(uploads.get(id), Some(Upload::Proof(_)))
        || uploads
            .values()
            .any(|u| matches!(u, Upload::Proof(p) if p.reserved_transfer() == Some(id)))
}
fn discard_owned_upload(
    uploads: &mut HashMap<String, Upload>,
    transfer: &str,
    h: &Header,
    context: &Context,
) {
    if uploads.get(transfer).is_some_and(|u| {
        matches!(u, Upload::File(u) if &u.owner == context
        && u.request_id == h.request_id
        && h.operation_id.as_deref() == Some(&uuid(u.operation.0)))
    }) {
        uploads.remove(transfer);
    }
}
fn retire_detached_delivery(
    context: &Context,
    pending: &mut [Pending],
    streams: &mut HashMap<String, ReadStream>,
    services: &mut HashMap<String, ServiceStream>,
) {
    for p in pending {
        if p.header.context.as_ref() == Some(context) && !p.mutation {
            p.cancelled = true;
            p.cancel.store(true, Ordering::SeqCst);
        }
    }
    for stream in streams
        .values_mut()
        .filter(|s| s.header.context.as_ref() == Some(context))
    {
        stream.ended = true;
    }
    for stream in services
        .values_mut()
        .filter(|s| s.header.context.as_ref() == Some(context))
    {
        stream.source = None;
        stream.bytes.clear();
        stream.offset = 0;
        stream.terminal = true;
    }
    // Existing entries/guards retain only outstanding issued-credit ownership.
    // The ordinary credit-drained or cancel path retires them; no extra map.
}
fn request_conflicts(
    h: &Header,
    pending: &[Pending],
    streams: &HashMap<String, ReadStream>,
    services: &HashMap<String, ServiceStream>,
    uploads: &HashMap<String, Upload>,
    output: &VecDeque<Frame>,
) -> bool {
    pending.iter().any(|p| {
        p.header.request_id == h.request_id
            && !(p.lookup.is_some()
                && proof::lookup_frame(h)
                && p.header.context == h.context
                && p.header.operation_id == h.operation_id
                && p.header.stream_id == h.stream_id)
    }) || streams.iter().any(|(id, s)| {
        s.header.request_id == h.request_id
            && !(matches!(h.message, Message::Credit { .. })
                && h.stream_id.as_ref() == Some(id)
                && h.context == s.header.context)
    }) || services.iter().any(|(id, s)| {
        s.header.request_id == h.request_id
            && !(matches!(h.message, Message::Credit { .. })
                && h.stream_id.as_ref() == Some(id)
                && h.context == s.header.context)
    }) || uploads.iter().any(|(id, u)| {
        u.request_id() == h.request_id
            && !matches!(u,Upload::Proof(p) if p.accepts(h))
            && !(matches!(u, Upload::File(_))
                && h.context.as_ref() == Some(u.owner())
                && matches!(
                    &h.message,
                    Message::UploadChunk { transfer_id, .. }
                        | Message::UploadEnd { transfer_id, .. }
                        | Message::CreateCommit {transfer_id}
                        | Message::SaveCommit { transfer_id, .. }
                        | Message::SaveCommitOwned { transfer_id, .. }
                        if transfer_id == id
                ))
    }) || output.iter().any(|frame| {
        frame.header.request_id == h.request_id
            && !(matches!(h.message, Message::Credit { .. })
                && h.context == frame.header.context
                && h.stream_id == frame.header.stream_id
                && (h
                    .stream_id
                    .as_ref()
                    .is_some_and(|id| streams.contains_key(id) || services.contains_key(id))))
            && matches!(
                frame.header.message,
                Message::Receipt { .. }
                    | Message::ProofExisting { .. }
                    | Message::ProofMissing { .. }
                    | Message::ProofPrepared { .. }
                    | Message::ProofOutputEnd { .. }
                    | Message::ReadEnd { .. }
                    | Message::ServiceEvent { terminal: true, .. }
            )
    })
}
fn mutating(h: &Header) -> bool {
    matches!(
        h.message,
        Message::SaveCommit { .. } | Message::SaveCommitOwned { .. } | Message::CreateCommit { .. }
    ) || matches!(&h.message, Message::ServiceCall { call } if call.mutating())
}
// This receipt is emitted only at an admission gate, before dispatch. Generic
// worker errors never acquire this no-effect proof based on their error code.
fn admission_refusal(
    shared: &Shared,
    h: &Header,
    code: ErrorCode,
    message: &str,
) -> io::Result<Frame> {
    if mutating(h)
        && !matches!(&h.message, Message::ServiceCall { call } if call.unprepared_worktree_mutation())
    {
        let operation = OperationID(id(h
            .operation_id
            .as_deref()
            .ok_or_else(|| error("operation missing"))?)?);
        Ok(receipt(
            h,
            buntrail_services::files::failure(
                operation,
                shared.dispatcher.files.target().clone(),
                CoreError::new(code, message),
            ),
        ))
    } else {
        Ok(reply(
            h,
            Message::Error {
                code: match code {
                    ErrorCode::Busy => "busy".into(),
                    ErrorCode::Unavailable => "unavailable".into(),
                    other => format!("{other:?}"),
                },
                safe_message: message.into(),
            },
        ))
    }
}
fn spawn_request(
    completion: &Waker,
    shared: &Arc<Shared>,
    pending: &mut Vec<Pending>,
    h: &Header,
    request: Request,
) -> io::Result<Option<Frame>> {
    if pending.iter().any(|p| p.header.request_id == h.request_id) {
        return Err(error("pending request ID conflict"));
    }
    let busy = || {
        admission_refusal(
            shared,
            h,
            ErrorCode::Busy,
            "request capacity reached before acceptance",
        )
        .map(Some)
    };
    let control = matches!(&request, Request::Service { call, .. } if call.unprepared_worktree_mutation())
        || matches!(
            &request,
            Request::Inspect(_)
                | Request::Observed(_)
                | Request::Service {
                    call: Call::Inspect
                        | Call::GitExisting { .. }
                        | Call::TerminalEnd { .. }
                        | Call::TerminalInput { .. }
                        | Call::TerminalResize { .. },
                    ..
                }
        );
    // Eight data owners cannot consume the four reserved control positions.
    if pending.len() >= if control { 12 } else { 8 } {
        return busy();
    }
    let (service_kind, cancel, mutation) = match &request {
        Request::Service { call, cancel, .. } => (
            match call {
                call if call.unprepared_worktree_mutation() => 0,
                Call::Inspect
                | Call::GitExisting { .. }
                | Call::TerminalEnd { .. }
                | Call::TerminalInput { .. }
                | Call::TerminalResize { .. } => 0,
                Call::Watch { .. } => 2,
                Call::Search { .. } => 3,
                _ => 1,
            },
            cancel.clone(),
            call.effectful(),
        ),
        _ => (
            0,
            Arc::new(AtomicBool::new(false)),
            matches!(&request, Request::Save(_) | Request::SaveStaged { .. }),
        ),
    };
    let count = if service_kind != 0 {
        service_count(shared, service_kind)
    } else if control {
        &shared.controls
    } else {
        &shared.workers
    };
    let limit = match service_kind {
        1 => 8,
        3 => 2,
        _ => 4,
    };
    if count.fetch_add(1, Ordering::SeqCst) >= limit {
        count.fetch_sub(1, Ordering::SeqCst);
        return busy();
    }
    let guard = WorkGuard {
        shared: shared.clone(),
        control,
        service_kind,
    };
    let (tx, rx) = mpsc::sync_channel(1);
    // Input/resize admission and attachment replacement only mutate bounded in-memory state.
    // Admit in wire order before independent workers can reorder bytes or replace a newer cursor.
    // Retain the ordinary effectful Pending/WorkGuard through response delivery.
    enum Dispatch {
        Admitted(Result<Response, CoreError>),
        Deferred(Box<Request>),
    }
    let dispatch = if matches!(
        &request,
        Request::Service {
            call: Call::TerminalInput { .. }
                | Call::TerminalResize { .. }
                | Call::TerminalAttach { .. },
            ..
        }
    ) {
        Dispatch::Admitted(shared.dispatcher.handle_sync(request))
    } else {
        Dispatch::Deferred(Box::new(request))
    };
    let state = shared.clone();
    let completion = completion.clone();
    #[cfg(test)]
    let schedule = input_order_tests::schedule(shared, h.request_id);
    std::thread::spawn(move || {
        #[cfg(test)]
        input_order_tests::before(&schedule);
        let result = match dispatch {
            Dispatch::Admitted(result) => result,
            Dispatch::Deferred(request) => state.dispatcher.handle_sync(*request),
        };
        #[cfg(test)]
        input_order_tests::after(&schedule);
        let _ = tx.send((result, guard));
        completion.wake();
    });
    pending.push(Pending {
        lookup: None,
        header: h.clone(),
        receiver: rx,
        cancelled: false,
        cancel,
        mutation,
    });
    Ok(None)
}
fn file_ref(shared: &Shared, p: &str) -> io::Result<FileRef> {
    Ok(FileRef {
        target: shared.dispatcher.files.target().clone(),
        path: TargetPath::posix(decode_path(p).map_err(error)?).map_err(error)?,
        resolved_identity: None,
    })
}
fn unhex(s: &str) -> io::Result<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error("invalid digest"));
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(error)?;
    }
    Ok(out)
}
fn version(shared: &Shared, s: &str) -> io::Result<FileVersion> {
    let v: WireVersion = serde_json::from_str(s).map_err(error)?;
    Ok(FileVersion {
        target: shared.dispatcher.files.target().clone(),
        opaque_token: STANDARD.decode(v.opaque_token).map_err(error)?,
        content_digest: unhex(&v.content_digest)?,
        file_identity: STANDARD.decode(v.file_identity).map_err(error)?,
    })
}
pub(crate) fn connection(
    mut socket: UnixStream,
    shared: &Arc<Shared>,
    serial: u64,
) -> io::Result<()> {
    socket.set_nonblocking(true)?;
    let mut decoder = Decoder::default();
    let mut negotiated: Option<Negotiated> = None;
    let mut contexts: Vec<Context> = vec![];
    let mut bridge_owner: Option<Context> = None;
    let mut output: VecDeque<Frame> = VecDeque::new();
    let mut encoded: Option<Vec<u8>> = None;
    let mut written = 0;
    let mut pending: Vec<Pending> = vec![];
    let mut streams: HashMap<String, ReadStream> = HashMap::new();
    let mut services: HashMap<String, ServiceStream> = HashMap::new();
    let mut uploads: HashMap<String, Upload> = HashMap::new();
    let mut releases: Vec<(Header, WorkspaceLeaseID)> = Vec::new();
    let mut authentication: Option<std::ffi::OsString> = None;
    let mut idle = Instant::now();
    let signal = crate::framed::wait::Signal::new()?;
    let completion = signal.waker();
    let mut input = [0; 8192];
    loop {
        signal.drain()?;
        let mut blocked_output = false;
        let mut immediate = false;
        if let Some(frame) = output.front() {
            if encoded.is_none() {
                let bytes = frame.encode().map_err(error)?;
                if negotiated.as_ref().is_some_and(|n| {
                    u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize > n.max_header
                        || frame.payload.len() > n.max_payload
                }) {
                    return Err(error("response exceeds negotiated limit"));
                }
                encoded = Some(bytes);
            }
            let bytes = encoded.as_ref().unwrap();
            match socket.write(&bytes[written..]) {
                Ok(0) => return Err(error("socket closed")),
                Ok(n) => {
                    written += n;
                    if written == bytes.len() {
                        if let Message::Credit { bytes } = frame.header.message {
                            proof::issued_credit(&mut pending, &frame.header, bytes)?;
                        }
                        if let Message::Credit { bytes } = frame.header.message
                            && let Some(upload) = frame
                                .header
                                .stream_id
                                .as_ref()
                                .and_then(|s| uploads.get_mut(s))
                        {
                            upload.grant_credit(&frame.header, bytes)?;
                        }
                        output.pop_front();
                        encoded = None;
                        written = 0;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    blocked_output = true;
                }
                Err(e) => return Err(e),
            }
        }
        if output.len() >= 32 {
            return Err(error("outbound control capacity reached"));
        }
        if output.len() < 31
            && let Some(index) = releases.iter().position(|(_, lease)| {
                shared
                    .dispatcher
                    .terminal
                    .service
                    .owner_shutdown_ready(*lease)
            })
        {
            let (header, _) = releases.swap_remove(index);
            if let Some(context) = &header.context
                && !shared.leases.lock().map_err(error)?.owns(context, serial)
            {
                contexts.retain(|registered| registered != context);
            }
            output.push_back(reply(&header, Message::Ack {}));
        }
        for i in (0..pending.len()).rev() {
            if let Ok((result, guard)) = pending[i].receiver.try_recv() {
                let p = pending.swap_remove(i);
                if p.cancelled && p.lookup.is_none() {
                    continue;
                }
                let frame = match result {
                    Ok(Response::Proof(value)) => match *value {
                        proof::Completed::Lookup { identity, receipt } => {
                            drop(guard);
                            if let Some(receipt) = receipt {
                                reply(
                                    &p.header,
                                    Message::ProofExisting {
                                        receipt: buntrail_protocol::services::Receipt::from_core(
                                            &receipt,
                                        )
                                        .map_err(error)?,
                                    },
                                )
                            } else if matches!(
                                p.header.message,
                                Message::ProofLookupBegin {
                                    action: buntrail_protocol::types::ProofAction::Lookup,
                                    ..
                                }
                            ) {
                                reply(&p.header, Message::ProofMissing {})
                            } else if p.cancelled || uploads.len() >= 4 || pending.len() >= 8 {
                                admission_refusal(
                                    shared,
                                    &p.header,
                                    ErrorCode::Unavailable,
                                    "proof promotion unavailable",
                                )?
                            } else {
                                match proof::promote(shared, &p.header, serial, identity) {
                                    Ok((normal, ready)) => {
                                        match insert_proof_upload(&mut uploads, normal) {
                                            Ok(()) => ready,
                                            Err(e) => reply(
                                                &p.header,
                                                Message::Error {
                                                    code: format!("{:?}", e.code),
                                                    safe_message: e.message,
                                                },
                                            ),
                                        }
                                    }
                                    Err(e) => reply(
                                        &p.header,
                                        Message::Error {
                                            code: format!("{:?}", e.code),
                                            safe_message: e.message,
                                        },
                                    ),
                                }
                            }
                        }
                        proof::Completed::Reply(message) => reply(&p.header, message),
                        proof::Completed::Output(proof) => {
                            let mut header = p.header.clone();
                            let transfer = uuid(new_id().map_err(error)?);
                            header.stream_id = Some(transfer.clone());
                            header.sequence = None;
                            let begin = reply(
                                &header,
                                Message::ProofOutputBegin {
                                    transfer_id: transfer.clone(),
                                    total_length: proof.length,
                                },
                            );
                            services.insert(
                                transfer,
                                ServiceStream {
                                    header,
                                    proof: Some(proof),
                                    source: None,
                                    bytes: Vec::new(),
                                    offset: 0,
                                    credit: INITIAL_CREDIT,
                                    sequence: 0,
                                    digest: String::new(),
                                    terminal: false,
                                    _guard: guard,
                                },
                            );
                            begin
                        }
                    },
                    Ok(Response::Service(value)) => {
                        let stream = service_stream(&p.header, guard, Some(*value), None)?;
                        services.insert(stream.header.stream_id.clone().unwrap(), stream);
                        continue;
                    }
                    Ok(Response::Events(source)) => {
                        let stream = service_stream(&p.header, guard, None, Some(source))?;
                        services.insert(stream.header.stream_id.clone().unwrap(), stream);
                        continue;
                    }
                    Ok(Response::Receipt(r)) => receipt(&p.header, *r),
                    Ok(Response::Read(snapshot)) => {
                        let transfer = uuid(new_id().map_err(error)?);
                        let mut header = p.header.clone();
                        header.stream_id = Some(transfer.clone());
                        let source: Box<dyn Read + Send> = match &snapshot.source {
                            ByteSource::Memory(b) => Box::new(Cursor::new(b.clone())),
                            ByteSource::PrivateSpool { local_path, .. } => {
                                let TargetPath::PosixBytes(bytes) = local_path else {
                                    return Err(error("invalid spool"));
                                };
                                use std::os::unix::ffi::OsStrExt;
                                Box::new(File::open(Path::new(std::ffi::OsStr::from_bytes(bytes)))?)
                            }
                        };
                        let Message::Read { ref path_base64 } = p.header.message else {
                            return Err(error("invalid read request"));
                        };
                        let begin = reply(
                            &header,
                            Message::ReadBegin {
                                transfer_id: transfer.clone(),
                                path_base64: path_base64.clone(),
                                version: serde_json::to_string(&wire_version(&snapshot.version))
                                    .map_err(error)?,
                                total_length: snapshot.size,
                            },
                        );
                        streams.insert(
                            transfer,
                            ReadStream {
                                header,
                                source,
                                _snapshot: *snapshot,
                                _guard: guard,
                                offset: 0,
                                ended: false,
                                credit: INITIAL_CREDIT,
                            },
                        );
                        begin
                    }
                    Err(e) => reply(
                        &p.header,
                        Message::Error {
                            code: format!("{:?}", e.code),
                            safe_message: e.message,
                        },
                    ),
                };
                output.push_back(frame);
            }
        }
        uploads.retain(|_, u| u.current());
        proof::poll_lookups(&mut pending, &mut output)?;
        match socket.read(&mut input) {
            Ok(0) => {
                decoder.finish().map_err(error)?;
                return Ok(());
            }
            Ok(n) => {
                idle = Instant::now();
                for frame in decoder
                    .push_helper_requests(
                        &input[..n],
                        |c| contexts.contains(c),
                        bridge_owner.as_ref(),
                    )
                    .map_err(error)?
                {
                    if let Some(limits) = &negotiated
                        && (serde_json::to_vec(&frame.header).map_err(error)?.len()
                            > limits.max_header
                            || frame.payload.len() > limits.max_payload
                            || frame.header.minor != limits.minor)
                    {
                        return Err(error("negotiated limits exceeded"));
                    }
                    let h = &frame.header;
                    let response = match &h.message {
                        Message::Hello { .. } if negotiated.is_none() => {
                            let limits = Negotiated::from_hello(h).map_err(error)?;
                            if shared.dispatcher.files.target().container.is_some()
                                && !limits.supports("container.binding.v1")
                            {
                                return Err(error(
                                    "Container identity/runtime capability required; existing supervisor remains running",
                                ));
                            }
                            let message = Message::Welcome {
                                capabilities: limits.capabilities.clone(),
                                max_header: limits.max_header as u32,
                                max_payload: limits.max_payload as u32,
                                initial_credit: INITIAL_CREDIT as u32,
                                target_binding: shared.binding.clone(),
                                runtime_generation: shared.runtime.clone(),
                                container_start_base64: shared
                                    .dispatcher
                                    .terminal
                                    .runtime
                                    .container_start
                                    .as_ref()
                                    .map(|s| STANDARD.encode(s)),
                            };
                            let mut response = reply(h, message);
                            response.header.minor = limits.minor;
                            negotiated = Some(limits);
                            Some(response)
                        }
                        Message::Register {
                            lease_id,
                            client_id,
                            workspace_id,
                            target_binding,
                            runtime_generation,
                        } if negotiated.as_ref().is_some_and(|n| n.supports("leases")) => {
                            if target_binding != &shared.binding
                                || runtime_generation != &shared.runtime
                            {
                                return Err(error("target or runtime mismatch"));
                            }
                            let c = Context {
                                workspace_id: workspace_id.clone(),
                                client_id: client_id.clone(),
                                target_binding: shared.binding.clone(),
                                runtime_generation: shared.runtime.clone(),
                            };
                            if bridge_owner
                                .as_ref()
                                .is_some_and(|old| old.client_id != c.client_id)
                            {
                                return Err(error("connection owner changed"));
                            }
                            {
                                let mut leases = shared.leases.lock().map_err(error)?;
                                shared
                                    .dispatcher
                                    .terminal
                                    .expire(&mut leases, Instant::now());
                                leases
                                    .register(lease_id.clone(), c.clone(), serial)
                                    .map_err(error)?;
                            }
                            shared
                                .dispatcher
                                .terminal
                                .service
                                .register_owner(
                                    shared
                                        .dispatcher
                                        .terminal
                                        .owner(lease_id, &c)
                                        .map_err(error)?,
                                )
                                .map_err(error)?;
                            bridge_owner.get_or_insert_with(|| c.clone());
                            if !contexts.contains(&c) {
                                contexts.push(c.clone());
                            }
                            let mut r = reply(h, Message::Ack {});
                            r.header.context = Some(c);
                            Some(r)
                        }
                        _ => {
                            let c = h
                                .context
                                .as_ref()
                                .filter(|c| {
                                    contexts.contains(c)
                                        || matches!(
                                            h.message,
                                            Message::Credit { .. } | Message::Cancel { .. }
                                        )
                                })
                                .ok_or_else(|| error("lease registration required"))?;
                            let active_owner = shared.leases.lock().map_err(error)?.owns(c, serial);
                            match &h.message {
                                // Detachment revokes new-work authority, not the ownership of
                                // already-issued credits/results. Controls below still match
                                // the authenticated context and exact stream/request owner.
                                _ if !active_owner
                                    && !matches!(
                                        h.message,
                                        Message::Credit { .. } | Message::Cancel { .. }
                                    ) =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "workspace is detached; resume its lease before new work",
                                    )?)
                                }
                                _ if request_conflicts(
                                    h, &pending, &streams, &services, &uploads, &output,
                                ) =>
                                {
                                    Some(reply(
                                        h,
                                        Message::Error {
                                            code: "invalid_argument".into(),
                                            safe_message: "request ID already has a live owner"
                                                .into(),
                                        },
                                    ))
                                }
                                _ if file_phase_targets_proof(&uploads, h)
                                    || matches!(&h.message, Message::UploadBegin { transfer_id, .. } if transfer_in_use(&uploads, transfer_id)) =>
                                {
                                    Some(reply(
                                        h,
                                        Message::Error {
                                            code: "invalid_argument".into(),
                                            safe_message: "transfer ID belongs to another upload"
                                                .into(),
                                        },
                                    ))
                                }
                                _ if (matches!(h.message, Message::UploadBegin { .. })
                                    || mutating(h))
                                    && !matches!(&h.message, Message::ServiceCall { call } if call.unprepared_worktree_mutation())
                                    && shared.mutation_admission_closed.load(Ordering::SeqCst) =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "mutation admission paused until storage maintenance succeeds",
                                    )?)
                                }
                                Message::ServiceCall { call }
                                    if call.requires_repository()
                                        && !negotiated
                                            .as_ref()
                                            .unwrap()
                                            .supports("git.repository.v1") =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "Repository capability was not negotiated",
                                    )?)
                                }
                                _ if proof::is_message(&h.message)
                                    && !negotiated
                                        .as_ref()
                                        .unwrap()
                                        .supports("git.worktree_proof")
                                    && !(negotiated
                                        .as_ref()
                                        .unwrap()
                                        .supports("git.original_lookup")
                                        && (matches!(
                                            h.message,
                                            Message::ProofLookupBegin {
                                                action:
                                                    buntrail_protocol::types::ProofAction::Lookup,
                                                ..
                                            }
                                        ) || proof::lookup_frame(h))) =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "Git worktree proof capability was not negotiated",
                                    )?)
                                }
                                Message::ProofLookupBegin {
                                    action: buntrail_protocol::types::ProofAction::Lookup,
                                    ..
                                } if !negotiated
                                    .as_ref()
                                    .unwrap()
                                    .supports("git.original_lookup") =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "Original lookup capability was not negotiated",
                                    )?)
                                }
                                Message::ProofLookupBegin { .. } => {
                                    proof::begin_lookup(shared, &mut pending, h)?
                                }
                                Message::ProofLookupChunk { .. }
                                | Message::ProofLookupEnd { .. } => {
                                    proof::receive_lookup(&mut pending, frame)?;
                                    None
                                }
                                Message::ProofObserveBegin { transfer_id, .. } => {
                                    if uploads.len() >= 4
                                        || pending.len() >= 8
                                        || transfer_in_use(&uploads, transfer_id)
                                    {
                                        Some(admission_refusal(
                                            shared,
                                            h,
                                            ErrorCode::Unavailable,
                                            "proof upload capacity reached",
                                        )?)
                                    } else {
                                        match proof::observe(shared, h, serial) {
                                            Ok(normal) => Some(
                                                match insert_proof_upload(&mut uploads, normal) {
                                                    Ok(()) => reply(h, Message::Ack {}),
                                                    Err(e) => reply(
                                                        h,
                                                        Message::Error {
                                                            code: format!("{:?}", e.code),
                                                            safe_message: e.message,
                                                        },
                                                    ),
                                                },
                                            ),
                                            Err(e) => Some(reply(
                                                h,
                                                Message::Error {
                                                    code: format!("{:?}", e.code),
                                                    safe_message: e.message,
                                                },
                                            )),
                                        }
                                    }
                                }
                                Message::ProofOriginalChunk { .. }
                                | Message::ProofOriginalEnd { .. }
                                | Message::ProofApprovalsBegin { .. }
                                | Message::ProofApprovalsChunk { .. }
                                | Message::ProofApprovalsEnd { .. }
                                | Message::ProofAliasesChunk { .. }
                                | Message::ProofAliasesEnd { .. } => {
                                    let key = uploads
                                        .iter()
                                        .find(|(_, u)| matches!(u,Upload::Proof(p) if p.accepts(h)))
                                        .map(|(id, _)| id.clone());
                                    if let Some(key) = key {
                                        let Upload::Proof(normal) = uploads.remove(&key).unwrap()
                                        else {
                                            unreachable!()
                                        };
                                        let header = h.clone();
                                        match normal.frame(
                                            shared,
                                            frame,
                                            &mut pending,
                                            authentication.clone(),
                                            negotiated
                                                .as_ref()
                                                .unwrap()
                                                .supports("git.repository.v1"),
                                        ) {
                                            Ok(Some((normal, response))) => Some(
                                                match insert_proof_upload(&mut uploads, normal) {
                                                    Ok(()) => response,
                                                    Err(e) => reply(
                                                        &header,
                                                        Message::Error {
                                                            code: format!("{:?}", e.code),
                                                            safe_message: e.message,
                                                        },
                                                    ),
                                                },
                                            ),
                                            Ok(None) => None,
                                            Err(e) => Some(reply(
                                                &header,
                                                Message::Error {
                                                    code: format!("{:?}", e.code),
                                                    safe_message: e.message,
                                                },
                                            )),
                                        }
                                    } else {
                                        Some(reply(
                                            h,
                                            Message::Error {
                                                code: "unavailable".into(),
                                                safe_message: "proof transfer has no live owner"
                                                    .into(),
                                            },
                                        ))
                                    }
                                }
                                Message::ProofCancel { .. } | Message::ProofRelease { .. } => {
                                    proof::cleanup(shared, &mut pending, h, serial)?
                                }
                                Message::Authentication { ssh_auth_sock } => {
                                    use std::os::unix::ffi::OsStringExt;
                                    authentication = ssh_auth_sock
                                        .as_ref()
                                        .map(|s| {
                                            decode_path(s)
                                                .map(std::ffi::OsString::from_vec)
                                                .map_err(error)
                                        })
                                        .transpose()?;
                                    Some(reply(h, Message::Ack {}))
                                }
                                Message::Release { lease_id, intent } => {
                                    if releases.len() >= 256 {
                                        return Err(error("lease retirement capacity reached"));
                                    }
                                    shared
                                        .leases
                                        .lock()
                                        .map_err(error)?
                                        .release(
                                            lease_id,
                                            c,
                                            serial,
                                            intent.clone(),
                                            Instant::now(),
                                        )
                                        .map_err(error)?;
                                    if *intent == ReleaseIntent::ResolvedWorkspaceClosure {
                                        shared.dispatcher.terminal.service.revoke_owner(
                                            WorkspaceLeaseID(id(lease_id)?),
                                            TerminalEndIntent::FinalWorkspaceClose,
                                        );
                                        services
                                            .retain(|_, s| s.header.context.as_ref() != Some(c));
                                        streams.retain(|_, s| s.header.context.as_ref() != Some(c));
                                        uploads.retain(|_, u| u.owner() != c);
                                        for p in &mut pending {
                                            if p.header.context.as_ref() == Some(c) && !p.mutation {
                                                p.cancelled = true;
                                                p.cancel.store(true, Ordering::SeqCst);
                                            }
                                        }
                                        releases.push((h.clone(), WorkspaceLeaseID(id(lease_id)?)));
                                    } else {
                                        retire_detached_delivery(
                                            c,
                                            &mut pending,
                                            &mut streams,
                                            &mut services,
                                        );
                                        uploads.retain(|_, u| u.owner() != c);
                                    }
                                    shared.dispatcher.git.reap_observations();
                                    if *intent == ReleaseIntent::ResolvedWorkspaceClosure {
                                        None
                                    } else {
                                        Some(reply(h, Message::Ack {}))
                                    }
                                }
                                Message::Cancel { request_id } => {
                                    let known = pending
                                        .iter()
                                        .any(|p| p.header.request_id == *request_id)
                                        || services
                                            .values()
                                            .any(|s| s.header.request_id == *request_id)
                                        || streams
                                            .values()
                                            .any(|s| s.header.request_id == *request_id)
                                        || uploads.values().any(|u| u.request_id() == *request_id);
                                    if !known && !contexts.contains(c) {
                                        continue;
                                    }
                                    let mut outcome = CancelOutcome::Unknown;
                                    let mut mutation_may_execute = false;
                                    for p in &mut pending {
                                        if p.header.request_id == *request_id
                                            && p.header.context.as_ref() == Some(c)
                                        {
                                            p.cancelled = true;
                                            p.cancel.store(true, Ordering::SeqCst);
                                            if let Some(lookup) = &mut p.lookup {
                                                lookup.cancel();
                                            }
                                            mutation_may_execute |= p.mutation;
                                            if !p.mutation {
                                                outcome = CancelOutcome::ConfirmedCancel;
                                            }
                                        }
                                    }
                                    services.retain(|_, stream| {
                                        let keep = stream.header.request_id != *request_id
                                            || stream.header.context.as_ref() != Some(c);
                                        if !keep {
                                            if mutating(&stream.header) || matches!(&stream.header.message,Message::ServiceCall{call} if call.effectful()) {
                                                mutation_may_execute = true;
                                            } else {
                                                outcome = CancelOutcome::ConfirmedCancel;
                                            }
                                        }
                                        keep
                                    });
                                    streams.retain(|_, s| {
                                        let keep = s.header.request_id != *request_id
                                            || s.header.context.as_ref() != Some(c);
                                        if !keep {
                                            outcome = CancelOutcome::ConfirmedCancel;
                                        }
                                        keep
                                    });
                                    uploads.retain(|_, u| {
                                        let keep = u.request_id() != *request_id || u.owner() != c;
                                        if !keep {
                                            if matches!(u, Upload::Proof(_)) {
                                                mutation_may_execute = true;
                                            } else {
                                                outcome = CancelOutcome::ConfirmedCancel;
                                            }
                                        }
                                        keep
                                    });
                                    if mutation_may_execute {
                                        outcome = CancelOutcome::Unknown;
                                    }
                                    Some(reply(h, Message::Cancellation { outcome }))
                                }
                                Message::Credit { bytes } => {
                                    let sid = h
                                        .stream_id
                                        .as_ref()
                                        .ok_or_else(|| error("stream missing"))?;
                                    let owned = if let Some(stream) = services.get_mut(sid) {
                                        Some((&stream.header, &mut stream.credit))
                                    } else {
                                        streams.get_mut(sid).map(|s| (&s.header, &mut s.credit))
                                    };
                                    match owned {
                                        Some((owner, credit)) if owner.context.as_ref() == Some(c)
                                            && owner.request_id == h.request_id && owner.operation_id == h.operation_id
                                            && *credit + *bytes as usize <= INITIAL_CREDIT => {
                                                *credit += *bytes as usize;
                                                None
                                            }
                                        None if !contexts.contains(c) => None,
                                        // A drop can retire a stream before its queued credit
                                        // arrives. Refuse unmatched/excess credit without changing
                                        // any other owner's budget or closing the shared bridge.
                                        _ => Some(reply(h, Message::Error {
                                            code: "invalid_argument".into(),
                                            safe_message: "credit has no matching outstanding stream budget".into(),
                                        })),
                                    }
                                }
                                Message::FileList { path_base64 }
                                    if negotiated.as_ref().unwrap().supports("services") =>
                                {
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::Service {
                                            call: Call::List {
                                                file: buntrail_protocol::services::File {
                                                    path_base64: path_base64.clone(),
                                                    resolved_identity: None,
                                                },
                                            },
                                            operation: None,
                                            request: h.request_id,
                                            binding: shared.binding.clone(),
                                            owner: None,
                                            payload: Vec::new(),
                                            authentication: authentication.clone(),
                                            cancel: Arc::new(AtomicBool::new(false)),
                                        },
                                    )?
                                }
                                Message::ServiceCall {
                                    call: Call::LeaseObserve { owner },
                                } => {
                                    let observed = (|| {
                                        use buntrail_protocol::services::OwnerPresence;
                                        owner.validate()?;
                                        if !negotiated.as_ref().unwrap().supports("leases.observe")
                                        {
                                            return Err(CoreError::new(
                                                ErrorCode::Unavailable,
                                                "owner observation capability was not negotiated",
                                            ));
                                        }
                                        if owner.client_id != c.client_id
                                            || owner.target_binding != shared.binding
                                        {
                                            return Err(CoreError::new(
                                                ErrorCode::InvalidArgument,
                                                "observed owner client or target mismatch",
                                            ));
                                        }
                                        let current = shared.dispatcher.terminal.runtime.clone();
                                        let context = owner.context();
                                        let leases = shared
                                            .leases
                                            .lock()
                                            .map_err(|_| buntrail_protocol::services::invalid())?;
                                        leases
                                            .validate_observed_identity(&owner.lease_id, &context)
                                            .map_err(|message| {
                                                CoreError::new(ErrorCode::InvalidArgument, message)
                                            })?;
                                        let mut current_context = context.clone();
                                        current_context.runtime_generation =
                                            uuid(current.supervisor_boot);
                                        let lease = shared
                                            .dispatcher
                                            .terminal
                                            .owner(&owner.lease_id, &current_context)?;
                                        let retired = shared
                                            .dispatcher
                                            .terminal
                                            .service
                                            .observe_owner_retirement(&lease)?;
                                        if owner.container_start_base64.is_some()
                                            && !negotiated
                                                .as_ref()
                                                .unwrap()
                                                .supports("container.binding.v1")
                                        {
                                            return Err(CoreError::new(
                                                ErrorCode::Unavailable,
                                                "Container runtime observation capability was not negotiated",
                                            ));
                                        }
                                        let (presence, workers_retired) = if owner
                                            .runtime_generation
                                            != uuid(current.supervisor_boot)
                                            || owner.container_start()? != current.container_start
                                        {
                                            (OwnerPresence::RuntimeLost {}, false)
                                        } else {
                                            let presence = leases
                                                .observe(&owner.lease_id, &context, Instant::now())
                                                .map_err(|message| {
                                                    CoreError::new(
                                                        ErrorCode::InvalidArgument,
                                                        message,
                                                    )
                                                })?;
                                            (presence, retired)
                                        };
                                        Ok(Reply::LeaseObserved {
                                            owner: owner.clone(),
                                            runtime_generation: uuid(current.supervisor_boot),
                                            presence,
                                            workers_retired,
                                        })
                                    })();
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::Observed(observed),
                                    )?
                                }
                                Message::ServiceCall {
                                    call: buntrail_protocol::services::Call::FileResolve { .. },
                                } if !negotiated.as_ref().unwrap().supports("file.resolve") => {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "file resolution capability was not negotiated",
                                    )?)
                                }
                                Message::ServiceCall {
                                    call: Call::GitRead { .. },
                                } if !negotiated.as_ref().unwrap().supports("git.read") => {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "Git read capability was not negotiated",
                                    )?)
                                }
                                Message::ServiceCall {
                                    call: Call::GitExisting { .. },
                                } if !negotiated.as_ref().unwrap().supports("git.existing") => {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "Git request lookup capability was not negotiated",
                                    )?)
                                }
                                Message::ServiceCall { call }
                                    if call.terminal_lease().is_some()
                                        && !negotiated.as_ref().unwrap().supports("terminal") =>
                                {
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "terminal capability was not negotiated",
                                    )?)
                                }
                                Message::ServiceCall { call }
                                    if negotiated.as_ref().unwrap().supports("services") =>
                                {
                                    let owner = if let Some(lease) = call.terminal_lease() {
                                        if !shared
                                            .leases
                                            .lock()
                                            .map_err(error)?
                                            .owns_lease(lease, c, serial)
                                        {
                                            return Err(error("terminal lease owner mismatch"));
                                        }
                                        Some(
                                            shared
                                                .dispatcher
                                                .terminal
                                                .owner(lease, c)
                                                .map_err(error)?,
                                        )
                                    } else {
                                        None
                                    };
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::Service {
                                            call: call.clone(),
                                            operation: h
                                                .operation_id
                                                .as_deref()
                                                .map(id)
                                                .transpose()?
                                                .map(OperationID),
                                            request: h.request_id,
                                            binding: shared.binding.clone(),
                                            owner,
                                            payload: frame.payload.clone(),
                                            authentication: authentication.clone(),
                                            cancel: Arc::new(AtomicBool::new(false)),
                                        },
                                    )?
                                }
                                Message::Read { path_base64 }
                                    if negotiated.as_ref().unwrap().supports("file.read") =>
                                {
                                    if streams
                                        .values()
                                        .any(|s| s.header.request_id == h.request_id)
                                    {
                                        return Err(error("duplicate live read request ID"));
                                    }
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::Read(file_ref(shared, path_base64)?),
                                    )?
                                }
                                Message::UploadBegin {
                                    transfer_id,
                                    path_base64,
                                    total_length,
                                } if negotiated.as_ref().unwrap().supports("file.save") => {
                                    if uploads.len() >= 4
                                        || transfer_in_use(&uploads, transfer_id)
                                        || *total_length
                                            > (buntrail_services::files::MAX_DOCUMENT_BYTES * 2 + 4)
                                                as u64
                                        || h.stream_id.as_ref() != Some(transfer_id)
                                    {
                                        return Err(error("upload capacity or identity invalid"));
                                    }
                                    let staging = tempfile::NamedTempFile::new_in(
                                        shared.directory.join("uploads"),
                                    )?;
                                    staging.as_file().lock()?;
                                    uploads.insert(
                                        transfer_id.clone(),
                                        Upload::File(Box::new(FileUpload {
                                            owner: c.clone(),
                                            credit: INITIAL_CREDIT,
                                            staging,
                                            file: file_ref(shared, path_base64)?,
                                            operation: OperationID(id(h
                                                .operation_id
                                                .as_ref()
                                                .unwrap())?),
                                            verifier: TransferVerifier::new(
                                                transfer_id.clone(),
                                                *total_length,
                                            )
                                            .map_err(error)?,
                                            digest: None,
                                            length: *total_length,
                                            touched: Instant::now(),
                                            request_id: h.request_id,
                                        })),
                                    );
                                    Some(reply(h, Message::Ack {}))
                                }
                                Message::UploadChunk {
                                    transfer_id,
                                    offset,
                                } => {
                                    let u = uploads
                                        .get_mut(transfer_id)
                                        .ok_or_else(|| error("upload missing"))?;
                                    let Upload::File(u) = u else {
                                        return Err(error("file upload type mismatch"));
                                    };
                                    if &u.owner != c
                                        || h.operation_id.as_deref() != Some(&uuid(u.operation.0))
                                        || h.stream_id.as_ref() != Some(transfer_id)
                                    {
                                        return Err(error("upload owner mismatch"));
                                    }
                                    if frame.payload.len() > u.credit {
                                        return Err(error("upload credit exhausted"));
                                    }
                                    u.credit -= frame.payload.len();
                                    u.verifier
                                        .chunk(transfer_id, *offset, &frame.payload)
                                        .map_err(error)?;
                                    u.staging.write_all(&frame.payload)?;
                                    u.touched = Instant::now();
                                    Some(reply(
                                        h,
                                        Message::Credit {
                                            bytes: frame.payload.len() as u32,
                                        },
                                    ))
                                }
                                Message::UploadEnd {
                                    transfer_id,
                                    sha256,
                                } => {
                                    let u = uploads
                                        .get_mut(transfer_id)
                                        .ok_or_else(|| error("upload missing"))?;
                                    let Upload::File(u) = u else {
                                        return Err(error("file upload type mismatch"));
                                    };
                                    if &u.owner != c
                                        || h.operation_id.as_deref() != Some(&uuid(u.operation.0))
                                    {
                                        return Err(error("upload operation mismatch"));
                                    }
                                    let digest = unhex(sha256)?;
                                    u.verifier.end(transfer_id, digest).map_err(error)?;
                                    u.staging.as_file().sync_all()?;
                                    u.digest = Some(digest);
                                    u.touched = Instant::now();
                                    Some(reply(h, Message::Ack {}))
                                }
                                Message::SaveCommitOwned { transfer_id, .. }
                                    if !negotiated
                                        .as_ref()
                                        .unwrap()
                                        .supports("file.save_proof") =>
                                {
                                    discard_owned_upload(&mut uploads, transfer_id, h, c);
                                    Some(admission_refusal(
                                        shared,
                                        h,
                                        ErrorCode::Unavailable,
                                        "authenticated save capability was not negotiated",
                                    )?)
                                }
                                Message::SaveCommit { transfer_id, .. }
                                | Message::SaveCommitOwned { transfer_id, .. }
                                | Message::CreateCommit { transfer_id } => 'commit: {
                                    let actor =
                                        if let Message::SaveCommitOwned { lease_id, .. } =
                                            &h.message
                                        {
                                            let active = shared
                                                .leases
                                                .lock()
                                                .map_err(error)?
                                                .save_authority(lease_id, c, serial);
                                            let Some(active) = active else {
                                                discard_owned_upload(
                                                    &mut uploads,
                                                    transfer_id,
                                                    h,
                                                    c,
                                                );
                                                break 'commit Some(admission_refusal(
                                                    shared,
                                                    h,
                                                    ErrorCode::InvalidArgument,
                                                    "save lease owner mismatch",
                                                )?);
                                            };
                                            Some((
                                                shared
                                                    .dispatcher
                                                    .terminal
                                                    .owner(lease_id, c)
                                                    .map_err(error)?,
                                                active,
                                            ))
                                        } else {
                                            None
                                        };
                                    let (submitted_revision, expected_version, create) =
                                        match &h.message {
                                            Message::SaveCommit {
                                                submitted_revision,
                                                expected_version,
                                                ..
                                            }
                                            | Message::SaveCommitOwned {
                                                submitted_revision,
                                                expected_version,
                                                ..
                                            } => (
                                                *submitted_revision,
                                                expected_version.as_deref(),
                                                false,
                                            ),
                                            _ => (0, None, true),
                                        };
                                    let u = uploads
                                        .remove(transfer_id)
                                        .ok_or_else(|| error("upload missing"))?;
                                    let Upload::File(u) = u else {
                                        return Err(error("file upload type mismatch"));
                                    };
                                    if &u.owner != c
                                        || u.digest.is_none()
                                        || h.operation_id.as_deref() != Some(&uuid(u.operation.0))
                                    {
                                        return Err(error(
                                            "upload incomplete or operation mismatch",
                                        ));
                                    }
                                    let expected =
                                        expected_version.map(|s| version(shared, s)).transpose()?;
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::SaveStaged {
                                            operation: u.operation,
                                            file: u.file,
                                            expected_version: expected,
                                            revision: BufferRevision(submitted_revision),
                                            staging: u.staging,
                                            digest: u.digest.unwrap(),
                                            length: u.length,
                                            create,
                                            actor,
                                        },
                                    )?
                                }
                                Message::Inspect { operation_id }
                                    if negotiated.as_ref().unwrap().supports("operations") =>
                                {
                                    spawn_request(
                                        &completion,
                                        shared,
                                        &mut pending,
                                        h,
                                        Request::Inspect(OperationID(id(operation_id)?)),
                                    )?
                                }
                                _ => Some(reply(
                                    h,
                                    Message::Error {
                                        code: "unavailable".into(),
                                        safe_message: "capability or method unavailable".into(),
                                    },
                                )),
                            }
                        }
                    };
                    if let Some(response) = response {
                        output.push_back(response);
                    }
                    if output.len() > 32 {
                        return Err(error("control queue exceeded"));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }
        // Control frames are drained first; keep only one bounded data frame in the socket queue.
        if output.is_empty()
            && let Some(sid) = streams
                .iter()
                .find(|(_, s)| {
                    (!s.ended && (s.credit > 0 || s.offset == s._snapshot.size))
                        || (s.ended && s.credit == INITIAL_CREDIT)
                })
                .map(|(id, _)| id.clone())
        {
            let stream = streams.get_mut(&sid).unwrap();
            if stream.ended {
                streams.remove(&sid);
                immediate = true;
            } else if stream.offset == stream._snapshot.size {
                let end = reply(
                    &stream.header,
                    Message::ReadEnd {
                        transfer_id: sid.clone(),
                        sha256: hex(&stream._snapshot.version.content_digest),
                    },
                );
                output.push_back(end);
                stream.ended = true;
            } else {
                let mut payload = vec![
                    0;
                    stream
                        .credit
                        .min(65536)
                        .min((stream._snapshot.size - stream.offset) as usize)
                ];
                stream.source.read_exact(&mut payload)?;
                let mut chunk = reply(
                    &stream.header,
                    Message::ReadChunk {
                        transfer_id: sid.clone(),
                        offset: stream.offset,
                    },
                );
                stream.credit -= payload.len();
                stream.offset += payload.len() as u64;
                chunk.payload = payload;
                output.push_back(chunk);
            }
        }
        if output.is_empty() {
            let mut finished = None;
            for (sid, s) in &mut services {
                if let Some(proof) = &mut s.proof {
                    match proof.next(&s.header, &mut s.credit) {
                        Ok(Some(frame)) => {
                            if matches!(frame.header.message, Message::ProofOutputEnd { .. }) {
                                finished = Some(sid.clone());
                            }
                            output.push_back(frame);
                            break;
                        }
                        Ok(None) => continue,
                        Err(e) => {
                            output.push_back(reply(
                                &s.header,
                                Message::Error {
                                    code: "unavailable".into(),
                                    safe_message: e.to_string(),
                                },
                            ));
                            finished = Some(sid.clone());
                            break;
                        }
                    }
                }
                if s.bytes.is_empty() {
                    if let Some(source) = &mut s.source {
                        match source
                            .as_mut()
                            .poll_next(&mut TaskContext::from_waker(&completion))
                        {
                            Poll::Pending => continue,
                            Poll::Ready(None) => {
                                finished = Some(sid.clone());
                                break;
                            }
                            Poll::Ready(Some(value)) => {
                                let value = value.unwrap_or_else(Reply::error);
                                s.terminal = matches!(
                                    value,
                                    Reply::Terminal {
                                        event: buntrail_protocol::terminal::Event::ProcessExit { .. }
                                            | buntrail_protocol::terminal::Event::Ended { .. }
                                            | buntrail_protocol::terminal::Event::Expired
                                            | buntrail_protocol::terminal::Event::RuntimeLost
                                    } | Reply::SearchComplete
                                        | Reply::SearchCancelled
                                        | Reply::SearchLimited { .. }
                                        | Reply::Error { .. }
                                );
                                s.bytes = service_bytes(&value)?;
                                s.digest = hex(&sha2::Sha256::digest(&s.bytes));
                                s.offset = 0;
                            }
                        }
                    } else {
                        if s.credit == INITIAL_CREDIT {
                            finished = Some(sid.clone());
                            break;
                        }
                        continue;
                    }
                }
                if s.credit == 0 {
                    continue;
                }
                let n = (s.bytes.len() - s.offset).min(65536).min(s.credit);
                let mut frame = reply(
                    &s.header,
                    Message::ServiceEvent {
                        offset: s.offset as u64,
                        total_length: s.bytes.len() as u64,
                        sha256: s.digest.clone(),
                        terminal: s.terminal,
                    },
                );
                frame.header.sequence = Some(s.sequence);
                frame.payload = s.bytes[s.offset..s.offset + n].to_vec();
                s.credit -= n;
                s.offset += n;
                output.push_back(frame);
                if s.offset == s.bytes.len() {
                    if s.terminal {
                        s.source = None;
                        s.bytes.clear();
                        s.offset = 0;
                    } else {
                        s.bytes.clear();
                        s.offset = 0;
                        s.sequence += 1;
                    }
                }
                break;
            }
            if let Some(id) = finished {
                services.remove(&id);
                immediate = true;
            }
        }
        if negotiated.is_none() && idle.elapsed() > Duration::from_secs(5) {
            return Err(error("negotiation timeout"));
        }
        let buffered = streams.values().any(|s| {
            (!s.ended && (s.credit > 0 || s.offset == s._snapshot.size))
                || (s.ended && s.credit == INITIAL_CREDIT)
        }) || services.values().any(|s| {
            (s.offset < s.bytes.len() && s.credit > 0)
                || (s.bytes.is_empty()
                    && s.source.is_none()
                    && s.proof.is_none()
                    && s.credit == INITIAL_CREDIT)
        });
        if immediate || (!blocked_output && (buffered || !output.is_empty())) {
            continue;
        }
        // Proof ownership/absolute deadlines and terminal retirement keep their existing bounded checks.
        let conservative = !uploads.is_empty()
            || !releases.is_empty()
            || pending
                .iter()
                .any(|p| p.lookup.is_some() || proof::is_message(&p.header.message))
            || services.values().any(|s| s.proof.is_some());
        let deadline = if conservative {
            Some(Instant::now() + Duration::from_millis(2))
        } else if negotiated.is_none() {
            Some(idle + Duration::from_secs(5))
        } else {
            None
        };
        signal.wait(&socket, blocked_output, deadline)?;
    }
}

#[cfg(test)]
mod service_admission_tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};
    #[test]
    fn detachment_cancels_only_its_read_only_pending_delivery() {
        let owner = Context {
            client_id: uuid([1; 16]),
            workspace_id: uuid([2; 16]),
            target_binding: "verified".into(),
            runtime_generation: uuid([3; 16]),
        };
        let mut other = owner.clone();
        other.workspace_id = uuid([4; 16]);
        let make = |request_id, context, mutation| {
            let (_, receiver) = mpsc::sync_channel(1);
            Pending {
                lookup: None,
                header: Header {
                    major: 1,
                    minor: 0,
                    request_id,
                    context: Some(context),
                    operation_id: None,
                    stream_id: None,
                    sequence: None,
                    message: Message::Cancel { request_id: 1 },
                },
                receiver,
                cancelled: false,
                cancel: Arc::new(AtomicBool::new(false)),
                mutation,
            }
        };
        let mut pending = vec![
            make(1, owner.clone(), false),
            make(2, owner.clone(), true),
            make(3, other, false),
        ];
        retire_detached_delivery(
            &owner,
            &mut pending,
            &mut HashMap::new(),
            &mut HashMap::new(),
        );
        assert!(pending[0].cancelled && pending[0].cancel.load(Ordering::SeqCst));
        assert!(
            !pending[1].cancelled && !pending[1].cancel.load(Ordering::SeqCst),
            "possibly executing mutation must retain its worker/result ownership"
        );
        assert!(!pending[2].cancelled && !pending[2].cancel.load(Ordering::SeqCst));
    }
    #[test]
    fn eight_owned_service_jobs_leave_reserved_inspection_admission() {
        let dir = tempfile::tempdir().unwrap();
        let target = buntrail_services::connections::local::identity().unwrap();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            dispatcher: Arc::new(
                crate::framed::dispatcher::Dispatcher::new(target, dir.path().join("files"))
                    .unwrap(),
            ),
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            runtime: uuid([1; 16]),
            binding: "verified".into(),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        let call = Call::List {
            file: buntrail_protocol::services::File {
                path_base64: STANDARD.encode(dir.path().as_os_str().as_encoded_bytes()),
                resolved_identity: None,
            },
        };
        let mut pending = vec![];
        let mut h = Header {
            major: 1,
            minor: 0,
            request_id: 1,
            context: None,
            operation_id: None,
            stream_id: None,
            sequence: None,
            message: Message::ServiceCall { call: call.clone() },
        };
        for n in 1..=8 {
            h.request_id = n;
            assert!(
                spawn_request(
                    Waker::noop(),
                    &shared,
                    &mut pending,
                    &h,
                    Request::Service {
                        call: call.clone(),
                        operation: None,
                        request: n,
                        binding: shared.binding.clone(),
                        owner: None,
                        payload: Vec::new(),
                        authentication: None,
                        cancel: Arc::new(AtomicBool::new(false))
                    }
                )
                .unwrap()
                .is_none()
            );
        }
        h.request_id = 9;
        assert!(
            spawn_request(
                Waker::noop(),
                &shared,
                &mut pending,
                &h,
                Request::Inspect(OperationID([2; 16]))
            )
            .unwrap()
            .is_none(),
            "data service jobs consumed the reserved inspection admission"
        );
        assert_eq!(shared.controls.load(Ordering::SeqCst), 1);
        for n in 10..=12 {
            h.request_id = n;
            assert!(
                spawn_request(
                    Waker::noop(),
                    &shared,
                    &mut pending,
                    &h,
                    if n == 12 {
                        Request::Observed(Err(buntrail_protocol::services::invalid()))
                    } else {
                        Request::Service {
                            call: if n == 11 {
                                Call::GitExisting {
                                    worktree: buntrail_protocol::services::Worktree {
                                        path_base64: STANDARD
                                            .encode(dir.path().as_os_str().as_encoded_bytes()),
                                        common_directory_base64: String::new(),
                                    },
                                    expected: buntrail_protocol::services::GitState::from_core(
                                        &GitExpectedState {
                                            head: GitHead::Unborn(b"main".to_vec()),
                                            index_fingerprint: [0; 32],
                                            worktree_fingerprint: [0; 32],
                                        },
                                    ),
                                    command: buntrail_protocol::services::GitCommand::Commit {
                                        message: "read-only fixture".into(),
                                    },
                                }
                            } else {
                                Call::Inspect
                            },
                            operation: Some(OperationID([3; 16])),
                            request: n,
                            binding: shared.binding.clone(),
                            owner: None,
                            payload: Vec::new(),
                            authentication: None,
                            cancel: Arc::new(AtomicBool::new(false)),
                        }
                    }
                )
                .unwrap()
                .is_none()
            );
        }
        assert_eq!(shared.controls.load(Ordering::SeqCst), 4);
        h.request_id = 13;
        assert!(
            spawn_request(
                Waker::noop(),
                &shared,
                &mut pending,
                &h,
                Request::Inspect(OperationID([4; 16]))
            )
            .unwrap()
            .is_some()
        );
        assert_eq!(shared.controls.load(Ordering::SeqCst), 4);
    }

    fn legacy_worktree_saturation(controls_full: bool) {
        let (dir, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
        let expected = dispatcher
            .git
            .mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(expected.state, OperationState::Confirmed(_)));
        let record_path = dir.path().join("state/operations").join(format!(
            "{}.json",
            original
                .operation
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        let durable_before = std::fs::read(&record_path).unwrap();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            dispatcher: Arc::new(dispatcher),
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            runtime: uuid([1; 16]),
            binding: "fixture".into(),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(if controls_full { 4 } else { 0 }),
            requests: AtomicUsize::new(8),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        let call = Call::GitMutate {
            worktree: buntrail_protocol::services::Worktree::from_core(&original.worktree).unwrap(),
            expected: buntrail_protocol::services::GitState::from_core(&original.expected),
            command: buntrail_protocol::services::GitCommand::from_core(&original.command).unwrap(),
        };
        let h = Header {
            major: 1,
            minor: 0,
            request_id: 70,
            context: None,
            operation_id: Some(uuid(original.operation.0)),
            stream_id: None,
            sequence: None,
            message: Message::ServiceCall { call: call.clone() },
        };
        let mut pending = vec![];
        let response = spawn_request(
            Waker::noop(),
            &shared,
            &mut pending,
            &h,
            Request::Service {
                call,
                operation: Some(original.operation),
                request: 70,
                binding: shared.binding.clone(),
                owner: None,
                payload: vec![],
                authentication: None,
                cancel: Arc::new(AtomicBool::new(true)),
            },
        )
        .unwrap();
        if controls_full {
            assert!(
                matches!(response.unwrap().header.message, Message::Error { .. }),
                "lookup capacity cannot assert a new Failed receipt"
            );
            assert!(pending.is_empty());
        } else {
            assert!(
                response.is_none(),
                "full data admission must preserve bounded original-receipt lookup"
            );
            let (result, guard) = pending
                .remove(0)
                .receiver
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            let Response::Service(reply) = result.unwrap() else {
                panic!("missing service response")
            };
            let buntrail_protocol::services::Reply::Receipt { receipt } = *reply else {
                panic!("missing original receipt")
            };
            assert_eq!(
                receipt.core(shared.dispatcher.files.target()).unwrap(),
                expected
            );
            drop(guard);
        }
        assert_eq!(std::fs::read(record_path).unwrap(), durable_before);
        assert_eq!(
            shared
                .dispatcher
                .git
                .existing_receipt_sync(&original)
                .unwrap(),
            Some(expected)
        );
    }
    #[test]
    fn legacy_worktree_lookup_survives_full_data_admission() {
        legacy_worktree_saturation(false);
    }
    #[test]
    fn legacy_worktree_full_control_is_unresolved_not_failed() {
        legacy_worktree_saturation(true);
    }
}

#[cfg(test)]
mod terminal_maintenance_tests {
    use super::*;
    use std::sync::{Mutex, atomic::AtomicUsize};
    fn exchange(socket: &mut UnixStream, header: &Header) -> Frame {
        socket
            .write_all(
                &Frame {
                    header: header.clone(),
                    payload: vec![],
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
        let mut prefix = [0; 8];
        socket.read_exact(&mut prefix).unwrap();
        let size = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize
            + u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
        let mut bytes = vec![0; size];
        socket.read_exact(&mut bytes).unwrap();
        let mut encoded = prefix.to_vec();
        encoded.extend(bytes);
        Decoder::default()
            .push_authorized(&encoded, |_| true)
            .unwrap()
            .remove(0)
    }
    #[test]
    fn paused_mutation_storage_still_returns_the_original_worktree_receipt() {
        let (dir, dispatcher, original) =
            crate::framed::services::worktree_guard_tests::fixture(false);
        let expected = dispatcher
            .git
            .mutate_sync(original.clone(), &AtomicBool::new(false));
        assert!(matches!(expected.state, OperationState::Confirmed(_)));
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
            mutation_admission_closed: AtomicBool::new(true),
        });
        let (mut socket, server) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let state = shared.clone();
        let worker = std::thread::spawn(move || connection(server, &state, 1));
        let mut header = Header {
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
                    .map(|s| s.to_string())
                    .collect(),
                max_header: 65536,
                max_payload: 1048576,
            },
        };
        exchange(&mut socket, &header);
        header.request_id = 2;
        header.message = Message::Register {
            lease_id: uuid([1; 16]),
            client_id: uuid([2; 16]),
            workspace_id: uuid([3; 16]),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        };
        exchange(&mut socket, &header);
        header.request_id = 3;
        header.context = Some(Context {
            client_id: uuid([2; 16]),
            workspace_id: uuid([3; 16]),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        });
        header.operation_id = Some(uuid(original.operation.0));
        header.message = Message::ServiceCall {
            call: Call::GitMutate {
                worktree: buntrail_protocol::services::Worktree::from_core(&original.worktree)
                    .unwrap(),
                expected: buntrail_protocol::services::GitState::from_core(&original.expected),
                command: buntrail_protocol::services::GitCommand::from_core(&original.command)
                    .unwrap(),
            },
        };
        let response = exchange(&mut socket, &header);
        drop(socket);
        let _ = worker.join().unwrap();
        assert!(
            matches!(response.header.message, Message::ServiceEvent { .. }),
            "storage admission overtook original receipt lookup: {:?}",
            response.header.message
        );
        let buntrail_protocol::services::Reply::Receipt { receipt } =
            serde_json::from_slice(&response.payload).unwrap()
        else {
            panic!("missing receipt")
        };
        assert_eq!(
            receipt.core(shared.dispatcher.files.target()).unwrap(),
            expected
        );
    }
    #[test]
    fn paused_storage_allows_owner_end_and_release_and_counts_reaping() {
        let dir = tempfile::tempdir().unwrap();
        let target = buntrail_services::connections::local::identity().unwrap();
        let dispatcher = Arc::new(
            crate::framed::dispatcher::Dispatcher::new(target.clone(), dir.path().join("files"))
                .unwrap(),
        );
        let runtime = dispatcher.terminal.runtime.clone();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            runtime: uuid(runtime.supervisor_boot),
            binding: hex(&sha2::Sha256::digest(serde_json::to_vec(&target).unwrap())),
            dispatcher,
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        let owner = WorkspaceLease {
            client: ClientID([1; 16]),
            workspace: WorkspaceID([2; 16]),
            lease: WorkspaceLeaseID([3; 16]),
            runtime: runtime.clone(),
        };
        shared
            .dispatcher
            .terminal
            .service
            .register_owner(owner.clone())
            .unwrap();
        for n in [4, 5] {
            let result = shared
                .dispatcher
                .terminal
                .service
                .open_sync(TerminalOpenRequest {
                    operation: OperationID([n; 16]),
                    session: TerminalSessionID([n; 16]),
                    owner: owner.clone(),
                    target: target.clone(),
                    runtime: runtime.clone(),
                    directory: TargetPath::posix(
                        dir.path().as_os_str().as_encoded_bytes().to_vec(),
                    )
                    .unwrap(),
                    shell: TargetPath::posix(b"/bin/sh".to_vec()).unwrap(),
                    size: buntrail_protocol::terminal::size(80, 24).unwrap(),
                });
            assert!(matches!(result.state, OperationState::Confirmed(_)));
        }
        shared
            .mutation_admission_closed
            .store(true, Ordering::SeqCst);
        let (mut socket, server) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let state = shared.clone();
        let worker = std::thread::spawn(move || connection(server, &state, 1));
        let mut h = Header {
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
                    .map(|s| s.to_string())
                    .collect(),
                max_header: 65536,
                max_payload: 1048576,
            },
        };
        assert!(matches!(
            exchange(&mut socket, &h).header.message,
            Message::Welcome { .. }
        ));
        h.request_id = 2;
        h.message = Message::Register {
            lease_id: uuid(owner.lease.0),
            client_id: uuid(owner.client.0),
            workspace_id: uuid(owner.workspace.0),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        };
        assert!(matches!(
            exchange(&mut socket, &h).header.message,
            Message::Ack {}
        ));
        h.context = Some(Context {
            client_id: uuid(owner.client.0),
            workspace_id: uuid(owner.workspace.0),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        });
        let mut list = h.clone();
        list.request_id = 10;
        list.message = Message::ServiceCall {
            call: Call::List {
                file: buntrail_protocol::services::File {
                    path_base64: STANDARD.encode(dir.path().as_os_str().as_encoded_bytes()),
                    resolved_identity: None,
                },
            },
        };
        let listed = exchange(&mut socket, &list);
        assert!(matches!(
            listed.header.message,
            Message::ServiceEvent { .. }
        ));
        let mut wrong_cancel = h.clone();
        wrong_cancel.request_id = 11;
        wrong_cancel.context.as_mut().unwrap().workspace_id = uuid([9; 16]);
        wrong_cancel.message = Message::Cancel { request_id: 10 };
        assert!(matches!(
            exchange(&mut socket, &wrong_cancel).header.message,
            Message::Cancellation {
                outcome: CancelOutcome::Unknown
            }
        ));
        let mut credit = list.clone();
        credit.stream_id = listed.header.stream_id;
        credit.message = Message::Credit {
            bytes: listed.payload.len() as u32,
        };
        for invalid in 0..4 {
            let mut wrong = credit.clone();
            match invalid {
                0 => wrong.context.as_mut().unwrap().workspace_id = uuid([9; 16]),
                1 => wrong.request_id = 12,
                2 => wrong.operation_id = Some(uuid([9; 16])),
                _ => {
                    wrong.message = Message::Credit {
                        bytes: INITIAL_CREDIT as u32,
                    }
                }
            }
            assert!(
                matches!(
                    exchange(&mut socket, &wrong).header.message,
                    Message::Error { .. }
                ),
                "wrong owner/request/operation/excess credit must not change the retained stream budget"
            );
        }
        socket
            .write_all(
                &Frame {
                    header: credit,
                    payload: vec![],
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
        let mut ping = h.clone();
        ping.request_id = 13;
        ping.message = Message::Authentication {
            ssh_auth_sock: None,
        };
        assert!(matches!(
            exchange(&mut socket, &ping).header.message,
            Message::Ack {}
        ));
        h.request_id = 3;
        h.message = Message::ServiceCall {
            call: Call::TerminalEnd {
                lease_id: uuid(owner.lease.0),
                session_id: uuid([4; 16]),
                intent: buntrail_protocol::terminal::EndIntent::ExplicitClose,
            },
        };
        let ended = exchange(&mut socket, &h);
        assert!(matches!(
            serde_json::from_slice::<Reply>(&ended.payload).unwrap(),
            Reply::TerminalAck
        ));
        assert!(
            shared
                .dispatcher
                .terminal
                .service
                .verify_session(TerminalSessionID([4; 16]), &owner)
                .is_err()
        );
        h.request_id = 4;
        h.message = Message::Release {
            lease_id: uuid(owner.lease.0),
            intent: ReleaseIntent::ResolvedWorkspaceClosure,
        };
        assert!(matches!(
            exchange(&mut socket, &h).header.message,
            Message::Ack {}
        ));
        let mut late = h.clone();
        late.request_id = 99;
        late.stream_id = Some(uuid([99; 16]));
        late.message = Message::Credit { bytes: 1 };
        socket
            .write_all(
                &Frame {
                    header: late,
                    payload: vec![],
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
        let mut sibling = h.clone();
        sibling.request_id = 100;
        sibling.context = None;
        sibling.message = Message::Register {
            lease_id: uuid([9; 16]),
            client_id: uuid(owner.client.0),
            workspace_id: uuid([9; 16]),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        };
        let sibling_reply = exchange(&mut socket, &sibling);
        assert!(
            matches!(sibling_reply.header.message, Message::Ack {}),
            "late credit must not disturb a sibling registration: {:?}",
            sibling_reply
        );
        let retired_at_ack = shared.dispatcher.terminal.service.shutdown_ready();
        let until = Instant::now() + Duration::from_secs(5);
        while !shared.dispatcher.terminal.service.shutdown_ready() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!shared.dispatcher.terminal.service.has_sessions());
        drop(socket);
        let _ = worker.join().unwrap();
        assert!(
            retired_at_ack,
            "resolved-close ACK must wait for the owned PTY worker to retire"
        );
    }
}

#[cfg(test)]
mod input_order_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Condvar, Mutex, atomic::AtomicUsize};
    #[derive(Default)]
    pub(super) struct Inversion {
        completed: Mutex<Vec<u64>>,
        ready: Condvar,
    }
    static SCHEDULE: Mutex<Option<(usize, Arc<Inversion>)>> = Mutex::new(None);
    pub(super) fn schedule(shared: &Arc<Shared>, id: u64) -> Option<(Arc<Inversion>, u64)> {
        SCHEDULE
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(key, _)| *key == Arc::as_ptr(shared) as usize && [3, 4].contains(&id))
            .map(|(_, gate)| (gate.clone(), id))
    }
    pub(super) fn before(schedule: &Option<(Arc<Inversion>, u64)>) {
        if let Some((gate, 3)) = schedule {
            let (done, timeout) = gate
                .ready
                .wait_timeout_while(
                    gate.completed.lock().unwrap(),
                    Duration::from_secs(5),
                    |done| !done.contains(&4),
                )
                .unwrap();
            assert!(
                !timeout.timed_out() && done.contains(&4),
                "second worker never completed"
            );
        }
    }
    pub(super) fn after(schedule: &Option<(Arc<Inversion>, u64)>) {
        if let Some((gate, id)) = schedule {
            gate.completed.lock().unwrap().push(*id);
            gate.ready.notify_all();
        }
    }
    fn receive(socket: &mut UnixStream) -> Frame {
        let mut prefix = [0; 8];
        socket.read_exact(&mut prefix).unwrap();
        let size = u32::from_be_bytes(prefix[..4].try_into().unwrap()) as usize
            + u32::from_be_bytes(prefix[4..].try_into().unwrap()) as usize;
        let mut bytes = vec![0; size];
        socket.read_exact(&mut bytes).unwrap();
        let mut encoded = prefix.to_vec();
        encoded.extend(bytes);
        Decoder::default()
            .push_authorized(&encoded, |_| true)
            .unwrap()
            .remove(0)
    }
    fn send(socket: &mut UnixStream, h: &Header, bytes: &[u8]) {
        socket
            .write_all(
                &Frame {
                    header: h.clone(),
                    payload: bytes.to_vec(),
                }
                .encode()
                .unwrap(),
            )
            .unwrap();
    }
    #[test]
    fn pipelined_input_remains_in_wire_order_when_workers_finish_in_reverse() {
        let dir = tempfile::tempdir().unwrap();
        let target = buntrail_services::connections::local::identity().unwrap();
        let dispatcher = Arc::new(
            crate::framed::dispatcher::Dispatcher::new(target.clone(), dir.path().join("files"))
                .unwrap(),
        );
        let runtime = dispatcher.terminal.runtime.clone();
        let shared = Arc::new(Shared {
            wake: crate::framed::wait::Signal::new().unwrap(),
            directory: dir.path().into(),
            runtime: uuid(runtime.supervisor_boot),
            binding: hex(&sha2::Sha256::digest(serde_json::to_vec(&target).unwrap())),
            dispatcher,
            leases: Mutex::new(crate::framed::leases::Leases::default()),
            clients: AtomicUsize::new(0),
            workers: AtomicUsize::new(0),
            controls: AtomicUsize::new(0),
            requests: AtomicUsize::new(0),
            watchers: AtomicUsize::new(0),
            searches: AtomicUsize::new(0),
            mutation_admission_closed: AtomicBool::new(false),
        });
        let owner = WorkspaceLease {
            client: ClientID([1; 16]),
            workspace: WorkspaceID([2; 16]),
            lease: WorkspaceLeaseID([3; 16]),
            runtime: runtime.clone(),
        };
        shared
            .dispatcher
            .terminal
            .service
            .register_owner(owner.clone())
            .unwrap();
        let shell = dir.path().join("ordered-shell");
        std::fs::write(&shell, b"#!/bin/sh\nstty -echo\nprintf ready > ready\nwhile IFS= read -r line; do\n[ \"$line\" = STOP ] && break\nprintf '%s\\n' \"$line\" >> received\ndone\nprintf done > done\n").unwrap();
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        let receipt = shared
            .dispatcher
            .terminal
            .service
            .open_sync(TerminalOpenRequest {
                operation: OperationID([4; 16]),
                session: TerminalSessionID([5; 16]),
                owner: owner.clone(),
                target,
                runtime,
                directory: TargetPath::posix(dir.path().as_os_str().as_encoded_bytes().to_vec())
                    .unwrap(),
                shell: TargetPath::posix(shell.as_os_str().as_encoded_bytes().to_vec()).unwrap(),
                size: buntrail_protocol::terminal::size(80, 24).unwrap(),
            });
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("ready").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        let (mut socket, server) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(8)))
            .unwrap();
        let state = shared.clone();
        let worker = std::thread::spawn(move || connection(server, &state, 1));
        let mut h = Header {
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
                    .map(|v| v.to_string())
                    .collect(),
                max_header: 65536,
                max_payload: 1048576,
            },
        };
        send(&mut socket, &h, &[]);
        assert!(matches!(
            receive(&mut socket).header.message,
            Message::Welcome { .. }
        ));
        h.request_id = 2;
        h.message = Message::Register {
            lease_id: uuid(owner.lease.0),
            client_id: uuid(owner.client.0),
            workspace_id: uuid(owner.workspace.0),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        };
        send(&mut socket, &h, &[]);
        assert!(matches!(
            receive(&mut socket).header.message,
            Message::Ack {}
        ));
        h.context = Some(Context {
            client_id: uuid(owner.client.0),
            workspace_id: uuid(owner.workspace.0),
            target_binding: shared.binding.clone(),
            runtime_generation: shared.runtime.clone(),
        });
        h.message = Message::ServiceCall {
            call: Call::TerminalInput {
                lease_id: uuid(owner.lease.0),
                session_id: uuid([5; 16]),
            },
        };
        let gate = Arc::new(Inversion::default());
        *SCHEDULE.lock().unwrap() = Some((Arc::as_ptr(&shared) as usize, gate.clone()));
        for (id, bytes) in [(3, b"first\n".as_slice()), (4, b"second\n".as_slice())] {
            h.request_id = id;
            send(&mut socket, &h, bytes);
        }
        for _ in 0..2 {
            let frame = receive(&mut socket);
            assert!(matches!(
                serde_json::from_slice::<Reply>(&frame.payload).unwrap(),
                Reply::TerminalAck
            ));
        }
        h.request_id = 5;
        send(&mut socket, &h, b"STOP\n");
        let frame = receive(&mut socket);
        assert!(matches!(
            serde_json::from_slice::<Reply>(&frame.payload).unwrap(),
            Reply::TerminalAck
        ));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !dir.path().join("done").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        let bytes = std::fs::read(dir.path().join("received")).unwrap();
        shared.dispatcher.terminal.service.shutdown();
        while !shared.dispatcher.terminal.service.shutdown_ready() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(2));
        }
        drop(socket);
        let _ = worker.join().unwrap();
        *SCHEDULE.lock().unwrap() = None;
        assert_eq!(
            *gate.completed.lock().unwrap(),
            vec![4, 3],
            "worker completion inversion was not induced"
        );
        assert_eq!(
            bytes, b"first\nsecond\n",
            "input was reordered or repeated before PTY delivery"
        );
    }
}
