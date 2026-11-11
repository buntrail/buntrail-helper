//! Wire dispatch only: all filesystem, process and durable operation policy stays in services.
use crate::framed::dispatcher::{Dispatcher, Response};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use buntrail_core::contracts::{async_types::EventStream, *};
use buntrail_protocol::services as w;
use buntrail_services::contracts::SearchService;
use futures_core::Stream;
use std::{
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll, Waker},
};

impl Dispatcher {
    pub(crate) fn service(
        &self,
        call: w::Call,
        operation: Option<OperationID>,
        request: u64,
        binding: &str,
        cancel: &AtomicBool,
    ) -> Result<Response, CoreError> {
        let t = self.files.target();
        let operation = || operation.ok_or_else(w::invalid);
        let result = match call {
            w::Call::Repository { worktree } => w::Reply::Repository {
                snapshot: Box::new(self.git.repository_sync(worktree.core(t)?, cancel)?),
            },
            w::Call::Commit {
                worktree,
                oid,
                cursor,
            } => w::Reply::Commit {
                page: self.git.commit_sync(
                    CommitQuery {
                        worktree: worktree.core(t)?,
                        oid,
                        cursor,
                    },
                    cancel,
                )?,
            },
            w::Call::FilteredHistory {
                worktree,
                refs,
                cursor,
                filter,
            } => {
                let page = self.git.history_sync(
                    HistoryQuery {
                        worktree: worktree.core(t)?,
                        ref_filter: refs
                            .iter()
                            .map(|v| B64.decode(v).map_err(|_| w::invalid()))
                            .collect::<Result<_, _>>()?,
                        cursor: cursor
                            .map(|v| B64.decode(v).map_err(|_| w::invalid()))
                            .transpose()?,
                        filter: Some(filter),
                    },
                    cancel,
                )?;
                w::Reply::History {
                    commits: page.commits.iter().map(w::Commit::from_core).collect(),
                    continuation_edges: page.continuation_edges,
                    next_cursor: page.next_cursor.map(|v| B64.encode(v)),
                }
            }

            w::Call::FileResolve { root, purpose } => {
                let result = self.files.resolve_sync(root.core(t)?, purpose.core()?)?;
                w::Reply::FileResolved {
                    root: w::File::from_core(&result.root)?,
                    file: w::File::from_core(&result.file)?,
                    resolved_path: w::path(&result.resolved_path)?,
                    node_kind: result.kind.map(|k| format!("{k:?}")),
                    version: result.version.as_ref().map(w::version),
                }
            }
            w::Call::List { file } => w::Reply::List {
                entries: self
                    .files
                    .list_sync(file.core(t)?)?
                    .iter()
                    .map(|e| {
                        Ok(w::Entry {
                            file: w::File::from_core(&e.file)?,
                            display_name: e.display_name.clone(),
                            kind: format!("{:?}", e.kind),
                        })
                    })
                    .collect::<Result<_, CoreError>>()?,
            },
            w::Call::PathVersion { file } => w::Reply::Version {
                version: w::version(&self.files.path_version(file.core(t)?)?),
            },
            w::Call::Watch { file } => {
                return Ok(Response::Events(Box::pin(Watch(
                    buntrail_services::files::watcher::watch(t.clone(), file.core(t)?)?,
                ))));
            }
            w::Call::Search { request: r } => {
                let mut future = self.search.search(r.core(t, request)?);
                let Poll::Ready(stream) = future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                else {
                    return Err(w::invalid());
                };
                return Ok(Response::Events(Box::pin(Search(stream?))));
            }
            w::Call::FileMutate {
                file,
                expected,
                command,
            } => {
                let command = match command {
                    w::FileCommand::Trash {
                        confirmed_target,
                        confirmed_path,
                    } => {
                        if confirmed_target != binding || confirmed_path != file.path_base64 {
                            return Err(w::invalid());
                        }
                        FileMutation::Trash
                    }
                    w::FileCommand::CreateDirectory => FileMutation::CreateDirectory,
                    w::FileCommand::Rename { destination } => FileMutation::Rename {
                        destination: w::target_path(&destination)?,
                    },
                    w::FileCommand::Move { destination } => FileMutation::Move {
                        destination: w::target_path(&destination)?,
                    },
                    w::FileCommand::Remove {
                        confirmed_target,
                        confirmed_path,
                    } => {
                        if confirmed_target != binding || confirmed_path != file.path_base64 {
                            return Err(CoreError::new(
                                ErrorCode::InvalidArgument,
                                "Remote removal requires confirmation of the actual target and path",
                            ));
                        }
                        FileMutation::Remove
                    }
                    w::FileCommand::Delete {
                        confirmed_target,
                        confirmed_path,
                    } => {
                        if confirmed_target != binding || confirmed_path != file.path_base64 {
                            return Err(CoreError::new(
                                ErrorCode::InvalidArgument,
                                "Permanent remote deletion requires confirmation of the actual target and path",
                            ));
                        }
                        FileMutation::Delete
                    }
                };
                w::Reply::Receipt {
                    receipt: w::Receipt::from_core(
                        &self.files.mutate_sync(FileMutationRequest {
                            operation: operation()?,
                            file: file.core(t)?,
                            expected: expected
                                .map(|v| v.core(t))
                                .transpose()?
                                .map_or(ExpectedPathState::Absent, ExpectedPathState::Present),
                            command,
                        }),
                    )?,
                }
            }
            w::Call::Discover { file } => w::Reply::Discovered {
                worktree: self
                    .git
                    .discover_sync(file.core(t)?, cancel)?
                    .as_ref()
                    .map(w::Worktree::from_core)
                    .transpose()?,
            },
            w::Call::Contains { worktree, file } => w::Reply::Contains {
                value: self.git.contains_document_sync(
                    &worktree.core(t)?,
                    file.core(t)?,
                    cancel,
                )?,
            },
            w::Call::GitRead { worktree, query } => {
                let output = self.git.read_sync(worktree.core(t)?, query, cancel)?;
                w::Reply::GitRead {
                    stdout_base64: B64.encode(output.stdout),
                    stderr_base64: B64.encode(output.stderr),
                    success: output.success,
                }
            }
            w::Call::Status { worktree } => {
                let s = self.git.status_sync(worktree.core(t)?, cancel)?;
                let entries = |v: &[GitEntry]| {
                    v.iter()
                        .map(w::GitEntry::from_core)
                        .collect::<Result<_, _>>()
                };
                w::Reply::Status {
                    worktree: w::Worktree::from_core(&s.worktree)?,
                    state: w::GitState::from_core(&s.state),
                    staged: entries(&s.staged)?,
                    unstaged: entries(&s.unstaged)?,
                    untracked: entries(&s.untracked)?,
                    conflicts: entries(&s.conflicts)?,
                }
            }
            w::Call::Diff {
                worktree,
                path_base64,
                source,
            } => {
                let d = self.git.diff_sync(
                    DiffRequest {
                        worktree: worktree.core(t)?,
                        path: w::target_path(&path_base64)?,
                        source: source.core(),
                    },
                    cancel,
                )?;
                let (content, unavailable) = match d.content {
                    DiffContent::Text => ("Text", None),
                    DiffContent::Binary => ("Binary", None),
                    DiffContent::Unavailable(s) => ("Unavailable", Some(s)),
                };
                w::Reply::Diff {
                    source: w::DiffSource::from_core(&d.source),
                    content: content.into(),
                    unavailable,
                    change: format!("{:?}", d.change),
                    previous_path: d.previous_path.as_ref().map(w::path).transpose()?,
                    expected: w::GitState::from_core(&d.expected),
                    bytes_base64: B64.encode(d.bytes),
                }
            }
            w::Call::History {
                worktree,
                refs,
                cursor,
            } => {
                let h = self.git.history_sync(
                    HistoryQuery {
                        filter: None,
                        worktree: worktree.core(t)?,
                        ref_filter: refs
                            .iter()
                            .map(|r| B64.decode(r).map_err(|_| w::invalid()))
                            .collect::<Result<_, _>>()?,
                        cursor: cursor
                            .map(|r| B64.decode(r).map_err(|_| w::invalid()))
                            .transpose()?,
                    },
                    cancel,
                )?;
                w::Reply::History {
                    commits: h.commits.iter().map(w::Commit::from_core).collect(),
                    continuation_edges: h.continuation_edges,
                    next_cursor: h.next_cursor.map(|c| B64.encode(c)),
                }
            }
            w::Call::GitExisting {
                worktree,
                expected,
                command,
            } => w::Reply::GitExisting {
                receipt: self
                    .git
                    .existing_receipt_sync(&GitMutationRequest {
                        operation: operation()?,
                        worktree: worktree.core(t)?,
                        expected: expected.core()?,
                        command: command.core()?,
                    })?
                    .as_ref()
                    .map(w::Receipt::from_core)
                    .transpose()?,
            },
            w::Call::GitMutate {
                worktree,
                expected,
                command,
            } => {
                let request = GitMutationRequest {
                    operation: operation()?,
                    worktree: worktree.core(t)?,
                    expected: expected.core()?,
                    command: command.core()?,
                };
                let receipt = if request.command.changes_worktree() {
                    self.git.refuse_unprepared_worktree_sync(&request)?
                } else {
                    self.git.mutate_sync(request, cancel)
                };
                w::Reply::Receipt {
                    receipt: w::Receipt::from_core(&receipt)?,
                }
            }
            w::Call::LeaseObserve { .. }
            | w::Call::TerminalOpen { .. }
            | w::Call::TerminalAttach { .. }
            | w::Call::TerminalInput { .. }
            | w::Call::TerminalResize { .. }
            | w::Call::TerminalEnd { .. } => return Err(w::invalid()),
            w::Call::Inspect => w::Reply::Receipt {
                receipt: w::Receipt::from_core(&self.files.inspect_sync(operation()?, t.clone())?)?,
            },
        };
        Ok(Response::Service(Box::new(result)))
    }
}
struct Watch(EventStream<FileEvent>);

impl Stream for Watch {
    type Item = Result<w::Reply, CoreError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.as_mut().poll_next(cx).map(|o| {
            o.map(|e| {
                e.and_then(|e| {
                    let (file, event) = match e {
                        FileEvent::Changed(f) => (f, "changed"),
                        FileEvent::Removed(f) => (f, "removed"),
                        FileEvent::RescanRequired(f) => (f, "rescan_required"),
                    };
                    Ok(w::Reply::Watch {
                        file: w::File::from_core(&file)?,
                        event: event.into(),
                    })
                })
            })
        })
    }
}
struct Search(EventStream<SearchEvent>);
impl Stream for Search {
    type Item = Result<w::Reply, CoreError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0
            .as_mut()
            .poll_next(cx)
            .map(|o| o.map(|e| e.and_then(w::Reply::search)))
    }
}

#[cfg(test)]
pub(crate) mod worktree_guard_tests {
    use super::*;
    fn git(root: &std::path::Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    pub(crate) fn fixture(pull: bool) -> (tempfile::TempDir, Dispatcher, GitMutationRequest) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("repo");
        std::fs::create_dir(&root).unwrap();
        git(&root, &["init", "-b", "main"]);
        git(&root, &["config", "user.name", "Fixture"]);
        git(&root, &["config", "user.email", "fixture@example.invalid"]);
        std::fs::write(root.join("file"), "original").unwrap();
        git(&root, &["add", "file"]);
        git(&root, &["commit", "-m", "initial"]);
        git(&root, &["branch", "other"]);
        let dispatcher = Dispatcher::new(
            buntrail_services::connections::local::identity().unwrap(),
            dir.path().join("state"),
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let worktree = dispatcher
            .git
            .discover_sync(
                FileRef {
                    target: dispatcher.files.target().clone(),
                    path: TargetPath::posix(root.as_os_str().as_encoded_bytes().to_vec()).unwrap(),
                    resolved_identity: None,
                },
                &cancel,
            )
            .unwrap()
            .unwrap();
        let original = dispatcher
            .git
            .status_sync(worktree.clone(), &cancel)
            .unwrap();
        let command = if pull {
            GitMutation::PullFastForward {
                remote: root.as_os_str().as_encoded_bytes().to_vec(),
                reference: b"main".to_vec(),
            }
        } else {
            GitMutation::Checkout {
                reference: b"other".to_vec(),
            }
        };
        let request = GitMutationRequest {
            operation: OperationID([71; 16]),
            worktree,
            expected: original.state.clone(),
            command,
        };
        (dir, dispatcher, request)
    }
    fn unprepared(pull: bool) {
        let (dir, dispatcher, request) = fixture(pull);
        let original = request.expected.clone();
        let cancel = AtomicBool::new(false);
        let response = dispatcher
            .service(
                w::Call::GitMutate {
                    worktree: w::Worktree::from_core(&request.worktree).unwrap(),
                    expected: w::GitState::from_core(&request.expected),
                    command: w::GitCommand::from_core(&request.command).unwrap(),
                },
                Some(request.operation),
                1,
                "fixture",
                &cancel,
            )
            .unwrap();
        let Response::Service(reply) = response else {
            panic!("missing wire reply")
        };
        let w::Reply::Receipt { receipt } = *reply else {
            panic!("missing receipt")
        };
        assert!(
            matches!(
                receipt.core(dispatcher.files.target()).unwrap().state,
                OperationState::Failed(OperationFailure {
                    error: CoreError {
                        code: ErrorCode::Unavailable,
                        ..
                    },
                    effect: FailureEffect::ProvenNoEffect,
                    ..
                })
            ),
            "unprepared direct-wire worktree mutation must refuse before effects"
        );
        assert_eq!(
            dispatcher
                .git
                .status_sync(request.worktree.clone(), &cancel)
                .unwrap()
                .state,
            original
        );
        assert!(
            dispatcher
                .git
                .existing_receipt_sync(&request)
                .unwrap()
                .is_none()
        );
        assert!(!dir.path().join("repo/.git/FETCH_HEAD").exists());
    }
    #[test]
    fn direct_wire_checkout_requires_target_preparation() {
        unprepared(false);
    }
    #[test]
    fn direct_wire_pull_requires_target_preparation() {
        unprepared(true);
    }
    #[test]
    fn helper_registration_and_owned_save_feed_the_target_verifier() {
        use buntrail_protocol::types::{Context, ReleaseIntent};
        use buntrail_services::git::worktree_proof::WorktreePreparation;
        use sha2::{Digest, Sha256};
        use std::io::Write;
        let (_dir, dispatcher, mut original) = fixture(false);
        let context = Context {
            client_id: w::uuid([10; 16]),
            workspace_id: w::uuid([11; 16]),
            target_binding: w::hex(&Sha256::digest(
                serde_json::to_vec(dispatcher.files.target()).unwrap(),
            )),
            runtime_generation: w::uuid(dispatcher.terminal.runtime.supervisor_boot),
        };
        let other_context = Context {
            workspace_id: w::uuid([12; 16]),
            ..context.clone()
        };
        let mut leases = crate::framed::leases::Leases::default();
        let id = w::uuid([13; 16]);
        let other_id = w::uuid([14; 16]);
        leases.register(id.clone(), context.clone(), 1).unwrap();
        leases
            .register(other_id.clone(), other_context.clone(), 1)
            .unwrap();
        let owner = dispatcher
            .observation_owner(&leases, &id, &context, 1)
            .unwrap();
        let other = dispatcher
            .observation_owner(&leases, &other_id, &other_context, 1)
            .unwrap();
        let TargetPath::PosixBytes(mut path) = original.worktree.canonical_path.clone() else {
            panic!()
        };
        path.extend_from_slice(b"/file");
        let file = FileRef {
            target: dispatcher.files.target().clone(),
            path: TargetPath::posix(path).unwrap(),
            resolved_identity: None,
        };
        let retained = dispatcher
            .git
            .observe_owned_sync(
                &owner,
                original.worktree.clone(),
                [Ok(file.clone())],
                &AtomicBool::new(false),
            )
            .unwrap();
        original.expected = retained.snapshot.state;
        let alias_digest = dispatcher
            .git
            .observation_alias_digest(&owner, retained.id)
            .unwrap();
        let version = Some(dispatcher.files.read_sync(file.clone()).unwrap().version);
        let content: [u8; 32] = Sha256::digest(b"helper save").into();
        let mut staging = tempfile::NamedTempFile::new().unwrap();
        staging.write_all(b"helper save").unwrap();
        let approval = GitSaveApproval {
            operation: OperationID([15; 16]),
            actor: other.registration().clone(),
            request_digest: buntrail_services::files::save_request_digest(
                &file,
                &version,
                BufferRevision(1),
                content,
            )
            .unwrap(),
        };
        let response = dispatcher
            .handle_sync(crate::framed::dispatcher::Request::SaveStaged {
                operation: approval.operation,
                file,
                expected_version: version,
                revision: BufferRevision(1),
                staging,
                digest: content,
                length: 11,
                create: false,
                actor: Some((
                    other.registration().clone(),
                    leases.save_authority(&other_id, &other_context, 1).unwrap(),
                )),
            })
            .unwrap();
        let Response::Receipt(receipt) = response else {
            panic!()
        };
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        leases
            .release(
                &other_id,
                &other_context,
                1,
                ReleaseIntent::ViewDetachment,
                std::time::Instant::now(),
            )
            .unwrap();
        let input = dispatcher
            .git
            .save_approval_input(&owner, [approval])
            .unwrap();
        let WorktreePreparation::Prepared(plan) = dispatcher
            .git
            .prepare_worktree_sync(
                &owner,
                &original,
                retained.id,
                alias_digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap()
        else {
            panic!()
        };
        let input = dispatcher.git.save_approval_input(&owner, []).unwrap();
        let receipt = dispatcher
            .git
            .execute_worktree_sync(
                &owner,
                original.clone(),
                plan,
                alias_digest,
                input,
                &AtomicBool::new(false),
            )
            .unwrap();
        assert!(matches!(receipt.state, OperationState::Confirmed(_)));
        assert_eq!(
            dispatcher.git.existing_receipt_sync(&original).unwrap(),
            Some(receipt)
        );
    }
}
