use buntrail_core::contracts::{async_types::ServiceFuture, *};
use buntrail_services::files::LocalFileService;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};
use std::{path::PathBuf, sync::Arc};
pub enum Request {
    Observed(Result<buntrail_protocol::services::Reply, CoreError>),
    Service {
        call: buntrail_protocol::services::Call,
        operation: Option<OperationID>,
        request: u64,
        binding: String,
        owner: Option<WorkspaceLease>,
        payload: Vec<u8>,
        authentication: Option<std::ffi::OsString>,
        cancel: Arc<std::sync::atomic::AtomicBool>,
    },
    Read(FileRef),
    Save(SaveRequest),
    SaveStaged {
        operation: OperationID,
        file: FileRef,
        expected_version: Option<FileVersion>,
        revision: BufferRevision,
        staging: tempfile::NamedTempFile,
        digest: [u8; 32],
        length: u64,
        create: bool,
        actor: Option<(WorkspaceLease, Arc<std::sync::atomic::AtomicBool>)>,
    },
    Inspect(OperationID),
}
pub enum Response {
    Proof(Box<crate::framed::transport::proof::Completed>),
    Service(Box<buntrail_protocol::services::Reply>),
    Events(buntrail_core::contracts::async_types::EventStream<buntrail_protocol::services::Reply>),
    Read(Box<FileSnapshot>),
    Receipt(Box<OperationReceipt>),
}
pub struct Dispatcher {
    pub files: Arc<LocalFileService>,
    pub terminal: crate::framed::terminal::SessionManager,
    pub git: buntrail_services::git::LocalGitService,
    pub search: buntrail_services::search::LocalSearchService,
}
impl Dispatcher {
    pub fn observation_owner(
        &self,
        leases: &crate::framed::leases::Leases,
        id: &str,
        context: &buntrail_protocol::types::Context,
        bridge: u64,
    ) -> Result<buntrail_services::git::observation::ObservationOwner, CoreError> {
        let binding = buntrail_protocol::services::hex(&Sha256::digest(
            serde_json::to_vec(self.files.target())
                .map_err(|_| buntrail_protocol::services::invalid())?,
        ));
        if context.target_binding != binding {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "observation registration target changed",
            ));
        }
        let active = leases.save_authority(id, context, bridge).ok_or_else(|| {
            CoreError::new(
                ErrorCode::Closed,
                "exact observation registration is not active",
            )
        })?;
        let owner = self.terminal.owner(id, context)?;
        Ok(
            buntrail_services::git::observation::ObservationOwner::authenticated(
                self.files.target().clone(),
                owner,
                active,
            ),
        )
    }
    pub fn new(target: TargetIdentity, directory: PathBuf) -> Result<Self, CoreError> {
        Self::new_with_start(target, directory, None)
    }
    pub fn new_with_start(
        target: TargetIdentity,
        directory: PathBuf,
        start: Option<Vec<u8>>,
    ) -> Result<Self, CoreError> {
        let files = Arc::new(LocalFileService::new(target, directory.clone())?);
        let ledger =
            buntrail_services::operations::ledger::Ledger::open(directory.join("operations"))?;
        let lock = ledger.lock()?;
        ledger.recover_and_compact(&lock)?;
        Ok(Self {
            terminal: crate::framed::terminal::SessionManager::new_with_start(
                files.clone(),
                &directory.join("runtimes"),
                start,
            )?,
            git: buntrail_services::git::LocalGitService::new(files.clone()),
            search: buntrail_services::search::LocalSearchService::bundled(files.clone()),
            files,
        })
    }
    pub fn compact(&self, directory: &std::path::Path) -> Result<(), CoreError> {
        let ledger = buntrail_services::operations::ledger::Ledger::open(
            directory.join("files/operations"),
        )?;
        let lock = ledger.lock()?;
        ledger.compact(&lock)
    }
    pub fn handle(&self, request: Request) -> ServiceFuture<'_, Result<Response, CoreError>> {
        Box::pin(async move { self.handle_sync(request) })
    }
    pub fn handle_sync(&self, request: Request) -> Result<Response, CoreError> {
        match request {
            Request::Observed(reply) => reply.map(|reply| Response::Service(Box::new(reply))),
            Request::Service {
                call,
                operation,
                request,
                binding,
                owner,
                payload,
                authentication,
                cancel,
            } => {
                if call.terminal_lease().is_some() {
                    return self.terminal.handle(
                        call,
                        operation,
                        owner.ok_or_else(buntrail_protocol::services::invalid)?,
                        self.files.target(),
                        authentication,
                        payload,
                    );
                }
                buntrail_services::git::authentication::with_authentication(authentication, || {
                    self.service(call, operation, request, &binding, &cancel)
                })
            }
            Request::Read(file) => self
                .files
                .read_sync(file)
                .map(|snapshot| Response::Read(Box::new(snapshot))),
            Request::Save(request) => {
                Ok(Response::Receipt(Box::new(self.files.save_sync(request))))
            }
            Request::SaveStaged {
                operation,
                file,
                expected_version,
                revision,
                mut staging,
                digest,
                length,
                create,
                actor,
            } => {
                let mut bytes = Vec::new();
                staging
                    .rewind()
                    .and_then(|_| {
                        staging
                            .take((buntrail_services::files::MAX_DOCUMENT_BYTES * 2 + 5) as u64)
                            .read_to_end(&mut bytes)
                    })
                    .map_err(|_| CoreError::new(ErrorCode::Io, "upload staging read failed"))?;
                if bytes.len() as u64 != length || Sha256::digest(&bytes).as_slice() != digest {
                    return Err(CoreError::new(
                        ErrorCode::InvalidArgument,
                        "completed upload changed before acceptance",
                    ));
                }
                if create {
                    return Ok(Response::Service(
                        buntrail_protocol::services::Reply::Receipt {
                            receipt: buntrail_protocol::services::Receipt::from_core(
                                &self.files.mutate_sync(FileMutationRequest {
                                    operation,
                                    file,
                                    expected: ExpectedPathState::Absent,
                                    command: FileMutation::Create {
                                        source: ByteSource::Memory(bytes.into()),
                                    },
                                }),
                            )?,
                        }
                        .into(),
                    ));
                }
                let request = SaveRequest {
                    operation,
                    file,
                    expected_version,
                    submitted_revision: revision,
                    source: ByteSource::Memory(bytes.into()),
                };
                let receipt = match actor {
                    Some((owner, active)) => self.files.save_owned_sync(request, owner, &active),
                    None => self.files.save_sync(request),
                };
                Ok(Response::Receipt(Box::new(receipt)))
            }
            Request::Inspect(id) => self
                .files
                .inspect_sync(id, self.files.target().clone())
                .map(|receipt| Response::Receipt(Box::new(receipt))),
        }
    }
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    use buntrail_protocol::types::{Context, ReleaseIntent};
    #[test]
    fn proof_owner_uses_the_exact_helper_registration_and_never_revives() {
        let dir = tempfile::tempdir().unwrap();
        let dispatcher = Dispatcher::new(
            buntrail_services::connections::local::identity().unwrap(),
            dir.path().join("state"),
        )
        .unwrap();
        let uuid = buntrail_protocol::services::uuid;
        let context = Context {
            client_id: uuid([1; 16]),
            workspace_id: uuid([2; 16]),
            target_binding: buntrail_protocol::services::hex(&Sha256::digest(
                serde_json::to_vec(dispatcher.files.target()).unwrap(),
            )),
            runtime_generation: uuid(dispatcher.terminal.runtime.supervisor_boot),
        };
        let id = uuid([3; 16]);
        let sibling = uuid([4; 16]);
        let mut leases = crate::framed::leases::Leases::default();
        leases.register(id.clone(), context.clone(), 1).unwrap();
        leases
            .register(sibling.clone(), context.clone(), 1)
            .unwrap();
        let owner = dispatcher
            .observation_owner(&leases, &id, &context, 1)
            .expect("helper must authenticate retained observation owner");
        let other = dispatcher
            .observation_owner(&leases, &sibling, &context, 1)
            .unwrap();
        let wrong = Context {
            target_binding: "wrong-target".into(),
            ..context.clone()
        };
        leases.register(uuid([9; 16]), wrong.clone(), 1).unwrap();
        assert!(
            dispatcher
                .observation_owner(&leases, &uuid([9; 16]), &wrong, 1)
                .is_err(),
            "proof owner adopted a foreign target registration"
        );
        assert!(
            dispatcher
                .observation_owner(&leases, &id, &context, 2)
                .is_err()
        );
        assert!(
            dispatcher
                .observation_owner(
                    &leases,
                    &id,
                    &Context {
                        client_id: uuid([8; 16]),
                        ..context.clone()
                    },
                    1
                )
                .is_err()
        );
        assert!(
            dispatcher
                .observation_owner(
                    &leases,
                    &id,
                    &Context {
                        workspace_id: uuid([8; 16]),
                        ..context.clone()
                    },
                    1
                )
                .is_err()
        );
        let wrong_runtime = Context {
            runtime_generation: uuid([8; 16]),
            ..context.clone()
        };
        leases
            .register(uuid([8; 16]), wrong_runtime.clone(), 1)
            .unwrap();
        assert!(
            dispatcher
                .observation_owner(&leases, &uuid([8; 16]), &wrong_runtime, 1)
                .is_err()
        );
        assert!(
            dispatcher
                .observation_owner(&leases, &uuid([5; 16]), &context, 1)
                .is_err()
        );
        leases
            .release(
                &id,
                &context,
                1,
                ReleaseIntent::ViewDetachment,
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(!owner.is_active());
        assert!(other.is_active());
        leases.register(id.clone(), context.clone(), 2).unwrap();
        assert!(!owner.is_active());
        let resumed = dispatcher
            .observation_owner(&leases, &id, &context, 2)
            .unwrap();
        leases.disconnect(2, std::time::Instant::now());
        assert!(!resumed.is_active());
        assert!(other.is_active());
        leases
            .register(sibling.clone(), context.clone(), 3)
            .unwrap();
        assert!(!other.is_active());
        let replaced = dispatcher
            .observation_owner(&leases, &sibling, &context, 3)
            .unwrap();
        leases
            .release(
                &sibling,
                &context,
                3,
                ReleaseIntent::ResolvedWorkspaceClosure,
                std::time::Instant::now(),
            )
            .unwrap();
        assert!(!replaced.is_active());
    }
}
