//! The supervisor owns sessions; bridge subscriptions only own output cursors.
use crate::framed::dispatcher::Response;
use buntrail_core::contracts::{async_types::EventStream, *};
use buntrail_protocol::{services as w, terminal as wire};
use buntrail_services::{
    contracts::TerminalService, files::LocalFileService, terminal::LocalTerminalService,
};
use futures_core::Stream;
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};
pub struct SessionManager {
    pub service: LocalTerminalService,
    pub runtime: RuntimeGeneration,
}
impl SessionManager {
    pub fn new(
        files: Arc<LocalFileService>,
        directory: &std::path::Path,
    ) -> Result<Self, CoreError> {
        Self::new_with_start(files, directory, None)
    }
    pub fn new_with_start(
        files: Arc<LocalFileService>,
        directory: &std::path::Path,
        start: Option<Vec<u8>>,
    ) -> Result<Self, CoreError> {
        let runtime = RuntimeGeneration {
            supervisor_boot: buntrail_services::connections::local::new_id()?,
            container_start: start,
        };
        Ok(Self {
            service: LocalTerminalService::for_supervisor(files, runtime.clone(), directory)?,
            runtime,
        })
    }
    pub fn expire(&self, leases: &mut crate::framed::leases::Leases, now: std::time::Instant) {
        for lease in leases.expire(now) {
            if let Ok(id) = w::id(&lease) {
                self.service
                    .revoke_owner(WorkspaceLeaseID(id), TerminalEndIntent::RetentionExpiry);
            }
        }
    }
    pub fn owner(
        &self,
        lease: &str,
        c: &buntrail_protocol::types::Context,
    ) -> Result<WorkspaceLease, CoreError> {
        if w::id(&c.runtime_generation)? != self.runtime.supervisor_boot {
            return Err(CoreError::new(
                ErrorCode::TargetChanged,
                "terminal runtime changed",
            ));
        }
        Ok(WorkspaceLease {
            client: ClientID(w::id(&c.client_id)?),
            workspace: WorkspaceID(w::id(&c.workspace_id)?),
            lease: WorkspaceLeaseID(w::id(lease)?),
            runtime: self.runtime.clone(),
        })
    }
    pub fn handle(
        &self,
        call: w::Call,
        operation: Option<OperationID>,
        owner: WorkspaceLease,
        target: &TargetIdentity,
        authentication: Option<std::ffi::OsString>,
        payload: Vec<u8>,
    ) -> Result<Response, CoreError> {
        let reply = match call {
            w::Call::TerminalOpen {
                session_id,
                directory_base64,
                shell_base64,
                columns,
                rows,
                ..
            } => w::Reply::Receipt {
                receipt: w::Receipt::from_core(&self.service.open_authenticated(
                    TerminalOpenRequest {
                        operation: operation.ok_or_else(w::invalid)?,
                        session: TerminalSessionID(w::id(&session_id)?),
                        owner,
                        target: target.clone(),
                        runtime: self.runtime.clone(),
                        directory: w::target_path(&directory_base64)?,
                        shell: w::target_path(&shell_base64)?,
                        size: wire::size(columns, rows)?,
                    },
                    authentication,
                ))?,
            },
            w::Call::TerminalAttach {
                session_id,
                last_output_sequence,
                ..
            } => {
                let request = TerminalAttachRequest {
                    session: TerminalSessionID(w::id(&session_id)?),
                    runtime: self.runtime.clone(),
                    owner,
                    last_output_sequence,
                };
                let mut future = self.service.attach(request);
                let Poll::Ready(result) = future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                else {
                    return Err(w::invalid());
                };
                return Ok(Response::Events(Box::pin(Events(result?))));
            }
            w::Call::TerminalInput { session_id, .. } => {
                let session = TerminalSessionID(w::id(&session_id)?);
                self.service.verify_session(session, &owner)?;
                self.service.input_sync(session, payload)?;
                w::Reply::TerminalAck
            }
            w::Call::TerminalResize {
                session_id,
                columns,
                rows,
                ..
            } => {
                let session = TerminalSessionID(w::id(&session_id)?);
                self.service.verify_session(session, &owner)?;
                self.service
                    .resize_sync(session, wire::size(columns, rows)?)?;
                w::Reply::TerminalAck
            }
            w::Call::TerminalEnd {
                session_id, intent, ..
            } => {
                let session = TerminalSessionID(w::id(&session_id)?);
                self.service.verify_session(session, &owner)?;
                self.service.end_sync(session, intent.core())?;
                w::Reply::TerminalAck
            }
            _ => return Err(w::invalid()),
        };
        Ok(Response::Service(Box::new(reply)))
    }
}
struct Events(EventStream<TerminalEvent>);
impl Stream for Events {
    type Item = Result<w::Reply, CoreError>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.0.as_mut().poll_next(cx) {
            Poll::Ready(None) => Poll::Ready(Some(Ok(w::Reply::error(CoreError::new(
                ErrorCode::Cancelled,
                "terminal renderer replaced",
            ))))),
            result => result.map(|v| {
                v.map(|r| {
                    r.map(|e| w::Reply::Terminal {
                        event: wire::Event::from_core(e),
                    })
                })
            }),
        }
    }
}
