use buntrail_protocol::types::{Context, ReleaseIntent};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub const RETENTION: Duration = Duration::from_secs(1800);
#[derive(Clone)]
pub struct Lease {
    pub context: Context,
    pub bridge: Option<u64>,
    pub disconnected_until: Option<Instant>,
    active: Arc<AtomicBool>,
}
#[derive(Default)]
pub struct Leases {
    values: HashMap<String, Lease>,
}
impl Drop for Leases {
    fn drop(&mut self) {
        for lease in self.values.values() {
            lease.active.store(false, Ordering::SeqCst);
        }
    }
}
impl Leases {
    pub fn register(
        &mut self,
        id: String,
        context: Context,
        bridge: u64,
    ) -> Result<(), &'static str> {
        if self.values.get(&id).is_some_and(|l| l.context != context) {
            return Err("lease owner mismatch");
        }
        if !self.values.contains_key(&id) && self.values.len() >= 256 {
            return Err("lease capacity reached");
        }
        if let Some(lease) = self.values.get(&id) {
            if lease.bridge == Some(bridge) {
                return Ok(());
            }
            lease.active.store(false, Ordering::SeqCst);
        }
        self.values.insert(
            id,
            Lease {
                context,
                bridge: Some(bridge),
                disconnected_until: None,
                active: Arc::new(AtomicBool::new(true)),
            },
        );
        Ok(())
    }
    pub fn owns(&self, context: &Context, bridge: u64) -> bool {
        self.values
            .values()
            .any(|l| &l.context == context && l.bridge == Some(bridge))
    }
    pub fn release(
        &mut self,
        id: &str,
        context: &Context,
        bridge: u64,
        intent: ReleaseIntent,
        now: Instant,
    ) -> Result<(), &'static str> {
        let l = self.values.get_mut(id).ok_or("lease missing")?;
        if &l.context != context || l.bridge != Some(bridge) {
            return Err("lease owner mismatch");
        }
        l.active.store(false, Ordering::SeqCst);
        if intent == ReleaseIntent::ResolvedWorkspaceClosure {
            self.values.remove(id);
        } else {
            l.bridge = None;
            l.disconnected_until = Some(now + RETENTION);
        }
        Ok(())
    }
    pub fn disconnect(&mut self, bridge: u64, now: Instant) {
        for l in self
            .values
            .values_mut()
            .filter(|l| l.bridge == Some(bridge))
        {
            l.active.store(false, Ordering::SeqCst);
            l.bridge = None;
            l.disconnected_until = Some(now + RETENTION);
        }
    }
    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let expired = self
            .values
            .iter()
            .filter(|(_, l)| l.disconnected_until.is_some_and(|d| d <= now))
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in &expired {
            if let Some(lease) = self.values.get(id) {
                lease.active.store(false, Ordering::SeqCst);
            }
            self.values.remove(id);
        }
        expired
    }
    pub fn owns_lease(&self, id: &str, context: &Context, bridge: u64) -> bool {
        self.values
            .get(id)
            .is_some_and(|l| &l.context == context && l.bridge == Some(bridge))
    }
    pub fn save_authority(
        &self,
        id: &str,
        context: &Context,
        bridge: u64,
    ) -> Option<Arc<AtomicBool>> {
        self.values
            .get(id)
            .filter(|lease| &lease.context == context && lease.bridge == Some(bridge))
            .map(|lease| lease.active.clone())
    }

    pub fn validate_observed_identity(
        &self,
        id: &str,
        context: &Context,
    ) -> Result<(), &'static str> {
        if self.values.get(id).is_some_and(|lease| {
            lease.context.client_id != context.client_id
                || lease.context.workspace_id != context.workspace_id
                || lease.context.target_binding != context.target_binding
        }) {
            return Err("observed lease owner mismatch");
        }
        Ok(())
    }
    pub fn observe(
        &self,
        id: &str,
        context: &Context,
        now: Instant,
    ) -> Result<buntrail_protocol::services::OwnerPresence, &'static str> {
        use buntrail_protocol::services::OwnerPresence;
        match self.values.get(id) {
            Some(lease) if &lease.context != context => Err("lease owner mismatch"),
            Some(lease) if lease.bridge.is_some() => Ok(OwnerPresence::Active {}),
            Some(lease) => Ok(OwnerPresence::Detached {
                remaining_millis: lease
                    .disconnected_until
                    .ok_or("missing retention deadline")?
                    .saturating_duration_since(now)
                    .as_millis() as u64,
            }),
            None => Ok(OwnerPresence::Absent {}),
        }
    }
    pub(crate) fn next_expiration(&self) -> Option<Instant> {
        self.values
            .values()
            .filter_map(|lease| lease.disconnected_until)
            .min()
    }
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn context(n: &str) -> Context {
        Context {
            client_id: n.into(),
            workspace_id: n.into(),
            target_binding: "target".into(),
            runtime_generation: "runtime".into(),
        }
    }
    #[test]
    fn exact_save_registration_revokes_without_reviving_same_context_sibling() {
        let mut leases = Leases::default();
        let c = context("one");
        leases.register("first".into(), c.clone(), 1).unwrap();
        leases.register("second".into(), c.clone(), 1).unwrap();
        let first = leases.save_authority("first", &c, 1).unwrap();
        let second = leases.save_authority("second", &c, 1).unwrap();
        assert!(leases.save_authority("missing", &c, 1).is_none());
        assert!(
            leases
                .save_authority("first", &context("wrong"), 1)
                .is_none()
        );
        assert!(leases.save_authority("first", &c, 2).is_none());
        let wrong_runtime = Context {
            runtime_generation: "other-runtime".into(),
            ..c.clone()
        };
        let wrong_target = Context {
            target_binding: "other-target".into(),
            ..c.clone()
        };
        assert!(leases.save_authority("first", &wrong_runtime, 1).is_none());
        assert!(leases.save_authority("first", &wrong_target, 1).is_none());
        leases
            .release(
                "first",
                &c,
                1,
                ReleaseIntent::ViewDetachment,
                Instant::now(),
            )
            .unwrap();
        assert!(
            !first.load(Ordering::SeqCst),
            "queued save retained detached lease authority"
        );
        assert!(
            second.load(Ordering::SeqCst),
            "same Context sibling was revoked"
        );
        leases.register("first".into(), c.clone(), 2).unwrap();
        assert!(
            !first.load(Ordering::SeqCst),
            "resume revived old acceptance authority"
        );
        let resumed = leases.save_authority("first", &c, 2).unwrap();
        leases.disconnect(2, Instant::now());
        assert!(!resumed.load(Ordering::SeqCst));
        assert!(second.load(Ordering::SeqCst));
        leases.register("second".into(), c.clone(), 3).unwrap();
        assert!(
            !second.load(Ordering::SeqCst),
            "bridge replacement retained old authority"
        );
        let replaced = leases.save_authority("second", &c, 3).unwrap();
        leases
            .release(
                "second",
                &c,
                3,
                ReleaseIntent::ResolvedWorkspaceClosure,
                Instant::now(),
            )
            .unwrap();
        assert!(!replaced.load(Ordering::SeqCst));
    }
    #[test]
    fn dropping_registration_table_revokes_outstanding_authority() {
        let mut leases = Leases::default();
        let context = context("owner");
        leases.register("lease".into(), context.clone(), 1).unwrap();
        let active = leases.save_authority("lease", &context, 1).unwrap();
        drop(leases);
        assert!(
            !active.load(Ordering::SeqCst),
            "registration table destruction left authority active"
        );
    }
    #[test]
    fn view_detachment_on_shared_bridge_expires_only_detached_owner() {
        for resume in [false, true] {
            let now = Instant::now();
            let mut leases = Leases::default();
            let a = context("a");
            let b = context("b");
            leases.register("a".into(), a.clone(), 1).unwrap();
            leases.register("b".into(), b.clone(), 1).unwrap();
            leases
                .release("a", &a, 1, ReleaseIntent::ViewDetachment, now)
                .unwrap();
            assert!(!leases.owns(&a, 1), "detached A still has bridge authority");
            assert!(leases.owns(&b, 1));
            assert!(
                leases
                    .expire(now + RETENTION - Duration::from_nanos(1))
                    .is_empty()
            );
            if resume {
                leases.register("a".into(), a.clone(), 1).unwrap();
            }
            let expired = leases.expire(now + RETENTION);
            assert_eq!(
                expired,
                if resume {
                    vec![]
                } else {
                    vec!["a".to_string()]
                }
            );
            assert!(leases.owns(&b, 1));
            assert_eq!(leases.owns(&a, 1), resume);
        }
    }
    #[test]
    fn detachment_disconnect_partial_recovery_and_explicit_release_are_distinct() {
        let now = Instant::now();
        let mut leases = Leases::default();
        let a = context("a");
        let b = context("b");
        leases.register("a".into(), a.clone(), 1).unwrap();
        leases.register("b".into(), b.clone(), 2).unwrap();
        leases
            .release("a", &a, 1, ReleaseIntent::ViewDetachment, now)
            .unwrap();
        assert!(!leases.owns(&a, 1));
        leases.disconnect(1, now + Duration::from_secs(1));
        assert!(!leases.owns(&a, 1));
        assert!(leases.owns(&b, 2));
        assert_eq!(leases.values["a"].disconnected_until, Some(now + RETENTION));
        leases.disconnect(2, now);
        leases.register("b".into(), b.clone(), 3).unwrap();
        leases.expire(now + RETENTION);
        assert!(!leases.values.contains_key("a"));
        assert!(leases.owns(&b, 3));
        leases
            .release("b", &b, 3, ReleaseIntent::ResolvedWorkspaceClosure, now)
            .unwrap();
        assert!(leases.is_empty());
    }

    #[test]
    fn event_wait_deadline_tracks_the_next_disconnected_owner_without_extending_it() {
        let mut leases = Leases::default();
        let now = Instant::now();
        leases.register("one".into(), context("one"), 1).unwrap();
        leases.register("two".into(), context("two"), 2).unwrap();
        assert_eq!(leases.next_expiration(), None);
        leases.disconnect(1, now);
        assert_eq!(
            leases.next_expiration(),
            Some(now + Duration::from_secs(1800))
        );
        leases.disconnect(2, now + Duration::from_secs(10));
        leases.register("one".into(), context("one"), 3).unwrap();
        assert_eq!(
            leases.next_expiration(),
            Some(now + Duration::from_secs(1810))
        );
        assert!(
            leases
                .expire(now + Duration::from_secs(1810) - Duration::from_nanos(1))
                .is_empty()
        );
        assert_eq!(leases.expire(now + Duration::from_secs(1810)), vec!["two"]);
        assert_eq!(leases.next_expiration(), None);
        assert!(leases.owns(&context("one"), 3));
    }
}
